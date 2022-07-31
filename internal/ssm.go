package internal

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2_types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssm_types "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/fatih/color"
	"github.com/spf13/viper"
)

const (
	maxOutputResults = 50
)

var (
	// default aws regions
	defaultAwsRegions = []string{
		"af-south-1",
		"ap-east-1", "ap-northeast-1", "ap-northeast-2", "ap-northeast-3", "ap-south-1", "ap-southeast-2", "ap-southeast-3",
		"ca-central-1",
		"cn-north-1", "cn-northwest-1",
		"eu-central-1", "eu-north-1", "eu-south-1", "eu-west-1", "eu-west-2", "eu-west-3",
		"me-south-1",
		"sa-east-1",
		"us-east-1", "us-east-2", "us-gov-east-1", "us-gov-west-2", "us-west-1", "us-west-2",
	}
)

type (
	Target struct {
		Name          string
		InstanceId    string
		PublicDomain  string
		PrivateDomain string
		PublicIp      string
		PrivateIp     string
		LaunchTime    *time.Time
		Tags          map[string]string
	}

	User struct {
		Name string
	}

	Region struct {
		Name string
	}

	Port struct {
		Remote string
		Local  string
	}

	fieldTag int
	Field struct {
		// The kind of field that this is
		tag fieldTag
		// If a field takes a modifier (e.g. a tag name or atime format) this will be present
		value *string
	}
)

// The full list of fields that are allowed
func FieldFlags() string {
	fields := []string{
		"name",
		"id",
		"launch-time",
		"launch-time:GoDateFmt",
		"tag:TagName",
		"private-ip",
		"public-ip",
		"private-dns",
		"public-dns",
	}
	return strings.Join(fields, ",")
}

func newFieldFromFlag(val string) (*Field, error) {
	switch {
	case val == "name":
		return &Field{tag: name, value: nil}, nil
	case val == "id":
		return &Field{tag: instanceId, value: nil}, nil
	case val == "launch-time":
		defaultVal := "2006-01-02T03:04"
		return &Field{tag: launchTime, value: &defaultVal}, nil
	case strings.HasPrefix(val, "launch-time:"):
		formatPart := strings.SplitN(val, ":", 2)[1]
		return &Field{tag: launchTime, value: &formatPart}, nil
	case strings.HasPrefix(val, "tag:"):
		tagName := strings.SplitN(val, ":", 2)[1]
		return &Field{tag: tag, value: &tagName}, nil
	case val == "private-ip":
		return &Field{tag: privateIp}, nil
	case val == "public-ip":
		return &Field{tag: publicIp}, nil
	case val == "private-dns":
		return &Field{tag: privateDomain}, nil
	case val == "public-dns":
		return &Field{tag: publicDomain}, nil
	default:
		return nil, fmt.Errorf("Unsupported field: %s", val)
	}
}

const (
	name fieldTag = iota
	instanceId
	launchTime
	// An AWS instance tag
	tag
	privateDomain
	publicDomain
	privateIp
	publicIp
)

func (t Target) getFieldForDisplay(field Field) string {
	valOrTilde := func(val string) string {
		if val != "" {
			return val
		} else {
			return "~"
		}
	}

	switch field.tag {
	case name:
		return t.Name
	case instanceId:
		return t.InstanceId
	case launchTime:
		return t.LaunchTime.Format(*field.value)
	case tag:
		val, exists := t.Tags[*field.value]
		if !exists {
			val = "~"
		}
		return val
	case publicDomain:
		return valOrTilde(t.PublicDomain)
	case privateDomain:
		return valOrTilde(t.PrivateDomain)
	case publicIp:
		return valOrTilde(t.PublicIp)
	case privateIp:
		return valOrTilde(t.PrivateIp)
	}
	log.Fatalf("Unexpected field %d", field)
	panic("unreachable")
}

// AskUser asks you which selects a user.
func AskUser() (*User, error) {
	prompt := &survey.Input{
		Message: "Type your connect ssh user (default: root):",
	}
	var user string
	survey.AskOne(prompt, &user)
	user = strings.TrimSpace(user)
	if user == "" {
		user = "root"
	}
	return &User{Name: user}, nil
}

// AskRegion asks you which selects a region.
func AskRegion(ctx context.Context, cfg aws.Config) (*Region, error) {
	var regions []string
	client := ec2.NewFromConfig(cfg)

	output, err := client.DescribeRegions(ctx, &ec2.DescribeRegionsInput{
		AllRegions: aws.Bool(true),
	})
	if err != nil {
		regions = make([]string, len(defaultAwsRegions))
		copy(regions, defaultAwsRegions)
	} else {
		regions = make([]string, len(output.Regions))
		for _, region := range output.Regions {
			regions = append(regions, aws.ToString(region.RegionName))
		}
	}
	sort.Strings(regions)

	var region string
	prompt := &survey.Select{
		Message: "Choose a region in AWS:",
		Options: regions,
	}
	if err := survey.AskOne(prompt, &region, survey.WithIcons(func(icons *survey.IconSet) {
		icons.SelectFocus.Format = "green+hb"
	}), survey.WithPageSize(20)); err != nil {
		return nil, err
	}

	return &Region{Name: region}, nil
}

// AskTarget asks you which selects an instance.
func AskTarget(ctx context.Context, cfg aws.Config) (*Target, error) {
	table, err := FindInstances(ctx, cfg)
	if err != nil {
		return nil, err
	}

	options := make([]string, 0, len(table))
	for k, _ := range table {
		options = append(options, k)
	}
	sort.Strings(options)
	if len(options) == 0 {
		return nil, fmt.Errorf("not found ec2 instances")
	}

	prompt := &survey.Select{
		Message: "Choose a target in AWS:",
		Options: options,
	}

	selectKey := ""
	if err := survey.AskOne(prompt, &selectKey, survey.WithIcons(func(icons *survey.IconSet) {
		icons.SelectFocus.Format = "green+hb"
	}), survey.WithPageSize(20)); err != nil {
		return nil, err
	}

	return table[selectKey], nil
}

// AskMultiTarget asks you which selects multi targets.
func AskMultiTarget(ctx context.Context, cfg aws.Config) ([]*Target, error) {
	table, err := FindInstances(ctx, cfg)
	if err != nil {
		return nil, err
	}

	options := make([]string, 0, len(table))
	for k, _ := range table {
		options = append(options, k)
	}
	sort.Strings(options)
	if len(options) == 0 {
		return nil, fmt.Errorf("not found multi-target")
	}

	prompt := &survey.MultiSelect{
		Message: "Choose targets in AWS:",
		Options: options,
	}

	var selectKeys []string
	if err := survey.AskOne(prompt, &selectKeys, survey.WithPageSize(20)); err != nil {
		return nil, err
	}

	var targets []*Target
	for _, k := range selectKeys {
		targets = append(targets, table[k])
	}
	return targets, nil
}

// AskPorts asks you which select ports.
func AskPorts() (port *Port, retErr error) {
	port = &Port{}
	prompts := []*survey.Question{
		{
			Name:   "remote",
			Prompt: &survey.Input{Message: "Remote port to access:"},
		},
		{
			Name:   "local",
			Prompt: &survey.Input{Message: "Local port number to forward:"},
		},
	}
	if err := survey.Ask(prompts, port); err != nil {
		retErr = WrapError(err)
		return
	}
	if _, err := strconv.Atoi(strings.TrimSpace(port.Remote)); err != nil {
		retErr = errors.New("you must specify a valid port number")
		return
	}
	if port.Local == "" {
		port.Local = port.Remote
	}

	if len(port.Remote) > 5 || len(port.Local) > 5 {
		retErr = errors.New("you must specify a valid port number")
		return
	}

	return
}

// FindInstances returns all of instances-map with running state.
func FindInstances(ctx context.Context, cfg aws.Config) (map[string]*Target, error) {
	var fields []*Field
	rawFields := viper.GetStringSlice("fields")
	if len(rawFields) == 0 {
		return nil, fmt.Errorf("[programming error] get list of fields to display")
	}
	for _, rawField := range rawFields {
		field, err := newFieldFromFlag(rawField)
		if err != nil {
			return nil, err
		}
		fields = append(fields, field)
	}
	//}

	var (
		client     = ec2.NewFromConfig(cfg)
		table      = make(map[string]*Target)
		outputFunc = func(table map[string]*Target, output *ec2.DescribeInstancesOutput) {
			var instances []Target
			for _, rv := range output.Reservations {
				for _, inst := range rv.Instances {
					name := ""
					tags := make(map[string]string)
					for _, tag := range inst.Tags {
						key, val := aws.ToString(tag.Key), aws.ToString(tag.Value)
						tags[key] = val
						if key == "Name" {
							name = val
						}
					}
					instances = append(instances, Target{
						Name:          name,
						InstanceId:    aws.ToString(inst.InstanceId),
						PublicDomain:  aws.ToString(inst.PublicDnsName),
						PrivateDomain: aws.ToString(inst.PrivateDnsName),
						PublicIp:      aws.ToString(inst.PublicIpAddress),
						PrivateIp:     aws.ToString(inst.PrivateIpAddress),
						LaunchTime:    inst.LaunchTime,
						Tags:          tags,
					})
				}
			}
			alignTable(table, instances, fields)
		}
	)

	// get instance ids which possibly can connect to instances using ssm.
	instances, err := FindInstanceIdsWithConnectedSSM(ctx, cfg)
	if err != nil {
		return nil, err
	}

	for len(instances) > 0 {
		max := len(instances)
		// The maximum number of filter values specified on a single call is 200.
		if max >= 200 {
			max = 199
		}
		output, err := client.DescribeInstances(ctx,
			&ec2.DescribeInstancesInput{
				Filters: []ec2_types.Filter{
					{Name: aws.String("instance-state-name"), Values: []string{"running"}},
					{Name: aws.String("instance-id"), Values: instances[:max]},
				},
			})
		if err != nil {
			return nil, err
		}
		outputFunc(table, output)
		instances = instances[max:]
	}

	return table, nil
}

func alignTable(table map[string]*Target, targets []Target, fields []*Field) {
	maxLen := make(map[Field]int)

	for _, target := range targets {
		for _, field := range fields {
			fieldVal := target.getFieldForDisplay(*field)
			if len(fieldVal) > maxLen[*field] {
				maxLen[*field] = len(fieldVal)
			}
		}
	}

	for _, target := range targets {
		var out string
		for i, field := range fields {
			fieldVal := target.getFieldForDisplay(*field)
			out += fieldVal
			if i != len(fields)-1 {
				out += strings.Repeat(" ", 2+maxLen[*field]-len(fieldVal))
			}
		}
		t := target // don't create a reference to the loop variable, which doesn't get recreated
		table[out] = &t
	}
}

// FindInstanceIdsWithConnectedSSM asks you which selects instances.
func FindInstanceIdsWithConnectedSSM(ctx context.Context, cfg aws.Config) ([]string, error) {
	var (
		instances  []string
		client     = ssm.NewFromConfig(cfg)
		outputFunc = func(instances []string, output *ssm.DescribeInstanceInformationOutput) []string {
			for _, inst := range output.InstanceInformationList {
				instances = append(instances, aws.ToString(inst.InstanceId))
			}
			return instances
		}
	)

	output, err := client.DescribeInstanceInformation(ctx, &ssm.DescribeInstanceInformationInput{MaxResults: maxOutputResults})
	if err != nil {
		return nil, err
	}
	instances = outputFunc(instances, output)

	// Repeat it when if output.NextToken exists.
	if aws.ToString(output.NextToken) != "" {
		token := aws.ToString(output.NextToken)
		for {
			if token == "" {
				break
			}
			nextOutput, err := client.DescribeInstanceInformation(ctx, &ssm.DescribeInstanceInformationInput{
				NextToken:  aws.String(token),
				MaxResults: maxOutputResults})
			if err != nil {
				return nil, err
			}
			instances = outputFunc(instances, nextOutput)

			token = aws.ToString(nextOutput.NextToken)
		}
	}

	return instances, nil
}

// FindInstanceIdByIp returns instance ids by ip.
func FindInstanceIdByIp(ctx context.Context, cfg aws.Config, ip string) (string, error) {
	var (
		instanceId string
		client     = ec2.NewFromConfig(cfg)
		outputFunc = func(output *ec2.DescribeInstancesOutput) string {
			for _, rv := range output.Reservations {
				for _, inst := range rv.Instances {
					if inst.PublicIpAddress == nil && inst.PrivateIpAddress == nil {
						continue
					}
					if ip == aws.ToString(inst.PublicIpAddress) || ip == aws.ToString(inst.PrivateIpAddress) {
						return *inst.InstanceId
					}
				}
			}
			return ""
		}
	)

	output, err := client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
		MaxResults: aws.Int32(maxOutputResults),
		Filters: []ec2_types.Filter{
			{Name: aws.String("instance-state-name"), Values: []string{"running"}},
		},
	})
	if err != nil {
		return "", err
	}

	instanceId = outputFunc(output)
	if instanceId != "" {
		return instanceId, nil
	}

	// Repeat it when if instanceId isn't found and output.NextToken exists.
	if aws.ToString(output.NextToken) != "" {
		token := aws.ToString(output.NextToken)
		for {
			if token == "" {
				break
			}
			nextOutput, err := client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
				MaxResults: aws.Int32(maxOutputResults),
				NextToken:  aws.String(token),
				Filters: []ec2_types.Filter{
					{Name: aws.String("instance-state-name"), Values: []string{"running"}},
				},
			})
			if err != nil {
				return "", err
			}

			instanceId = outputFunc(nextOutput)
			if instanceId != "" {
				return instanceId, nil
			}

			token = aws.ToString(nextOutput.NextToken)
		}
	}

	return "", nil
}

// FindDomainByInstanceId returns domain by instance id.
func FindDomainByInstanceId(ctx context.Context, cfg aws.Config, instanceId string) ([]string, error) {
	var (
		domain     []string
		client     = ec2.NewFromConfig(cfg)
		outputFunc = func(output *ec2.DescribeInstancesOutput, id string) []string {
			for _, rv := range output.Reservations {
				for _, inst := range rv.Instances {
					if aws.ToString(inst.InstanceId) == id {
						return []string{aws.ToString(inst.PublicDnsName), aws.ToString(inst.PrivateDnsName)}
					}
				}
			}
			return []string{}
		}
	)

	output, err := client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
		MaxResults: aws.Int32(maxOutputResults),
		Filters: []ec2_types.Filter{
			{Name: aws.String("instance-state-name"), Values: []string{"running"}},
		},
	})
	if err != nil {
		return []string{}, err
	}

	domain = outputFunc(output, instanceId)
	if len(domain) != 0 {
		return domain, nil
	}

	// Repeat it when if domain isn't found and output.NextToken exists.
	if aws.ToString(output.NextToken) != "" {
		token := aws.ToString(output.NextToken)
		for {
			if token == "" {
				break
			}
			nextOutput, err := client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
				MaxResults: aws.Int32(maxOutputResults),
				NextToken:  aws.String(token),
				Filters: []ec2_types.Filter{
					{Name: aws.String("instance-state-name"), Values: []string{"running"}},
				},
			})
			if err != nil {
				return []string{}, err
			}

			domain = outputFunc(nextOutput, instanceId)
			if len(domain) != 0 {
				return domain, nil
			}

			token = aws.ToString(nextOutput.NextToken)
		}
	}

	return []string{}, nil
}

// AskUser asks you which selects a user.
func AskHost() (host string, retErr error) {
	prompt := &survey.Input{
		Message: "Type your host address you want to forward to:",
	}
	survey.AskOne(prompt, &host)
	host = strings.TrimSpace(host)
	if host == "" {
		retErr = errors.New("you must specify a host address")
		return
	}
	return
}

// CreateStartSession creates start session.
func CreateStartSession(ctx context.Context, cfg aws.Config, input *ssm.StartSessionInput) (*ssm.StartSessionOutput, error) {
	client := ssm.NewFromConfig(cfg)

	return client.StartSession(ctx, input)
}

// DeleteStartSession creates session.
func DeleteStartSession(ctx context.Context, cfg aws.Config, input *ssm.TerminateSessionInput) error {
	client := ssm.NewFromConfig(cfg)
	fmt.Printf("%s %s \n", color.YellowString("Delete Session"),
		color.YellowString(aws.ToString(input.SessionId)))

	_, err := client.TerminateSession(ctx, input)
	return err
}

// SendCommand send commands to instance targets.
func SendCommand(ctx context.Context, cfg aws.Config, targets []*Target, command string) (*ssm.SendCommandOutput, error) {
	client := ssm.NewFromConfig(cfg)

	// only support to linux (window = "AWS-RunPowerShellScript")
	docName := "AWS-RunShellScript"

	var ids []string
	for _, t := range targets {
		ids = append(ids, t.InstanceId)
	}

	input := &ssm.SendCommandInput{
		DocumentName:   &docName,
		InstanceIds:    ids,
		TimeoutSeconds: 60,
		CloudWatchOutputConfig: &ssm_types.CloudWatchOutputConfig{
			CloudWatchOutputEnabled: true,
		},
		Parameters: map[string][]string{"commands": []string{command}},
	}

	return client.SendCommand(ctx, input)
}

// PrintCommandInvocation watches command invocations.
func PrintCommandInvocation(ctx context.Context, cfg aws.Config, inputs []*ssm.GetCommandInvocationInput) {
	client := ssm.NewFromConfig(cfg)

	wg := new(sync.WaitGroup)
	for _, input := range inputs {
		wg.Add(1)
		go func(input *ssm.GetCommandInvocationInput) {
		Exit:
			for {
				select {
				case <-time.After(1 * time.Second):
					output, err := client.GetCommandInvocation(ctx, input)
					if err != nil {
						color.Red("%v", err)
						break Exit
					}
					status := strings.ToLower(string(output.Status))
					switch status {
					case "pending", "inprogress", "delayed":
					case "success":
						fmt.Printf("[%s][%s] %s\n", color.GreenString("success"), color.YellowString(*output.InstanceId), color.GreenString(*output.StandardOutputContent))
						break Exit
					default:
						fmt.Printf("[%s][%s] %s\n", color.RedString("err"), color.YellowString(*output.InstanceId), color.RedString(*output.StandardErrorContent))
						break Exit
					}
				}
			}
			wg.Done()
		}(input)
	}

	wg.Wait()
}

// GenerateSSHExecCommand generates ssh exec command.
func GenerateSSHExecCommand(exec, identity, user, domain string) (newExec string) {
	if exec == "" {
		newExec = fmt.Sprintf("%s@%s", user, domain)
	} else {
		newExec = exec
	}

	opt := false
	for _, sep := range strings.Split(newExec, " ") {
		if sep == "-i" {
			opt = true
			break
		}
	}
	// if current ssh-exec don't exist -i option
	if !opt && identity != "" {
		// injection -i option
		newExec = fmt.Sprintf("-i %s %s", identity, newExec)
	}

	return
}

func PrintReady(cmd, region, target string) {
	fmt.Printf("[%s] region: %s, target: %s\n", color.GreenString(cmd), color.YellowString(region), color.YellowString(target))
}

// CallProcess calls process.
func CallProcess(process string, args ...string) error {
	call := exec.Command(process, args...)
	call.Stderr = os.Stderr
	call.Stdout = os.Stdout
	call.Stdin = os.Stdin

	// ignore signal(sigint)
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT)
	done := make(chan bool, 1)
	go func() {
		for {
			select {
			case <-sigs:
			case <-done:
				break
			}
		}
	}()
	defer close(done)

	// run subprocess
	if err := call.Run(); err != nil {
		return WrapError(err)
	}
	return nil
}
