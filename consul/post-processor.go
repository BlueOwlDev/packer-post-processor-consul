package consul

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/packer/helper/config"
	"github.com/mitchellh/goamz/aws"
	"github.com/mitchellh/goamz/ec2"
	"github.com/mitchellh/packer/common"
	"github.com/mitchellh/packer/packer"
)

var supported = map[string]string{
	"mitchellh.amazonebs":       "amazonebs",
	"mitchellh.amazon.instance": "amazoninstance",
}

type Config struct {
	common.PackerConfig `mapstructure:",squash"`

	AwsAccessKey  string `mapstructure:"aws_access_key"`
	AwsSecretKey  string `mapstructure:"aws_secret_key"`
	AwsToken      string `mapstructure:"aws_token"`
	ConsulAddress string `mapstructure:"consul_address"`
	ConsulScheme  string `mapstructure:"consul_scheme"`
	ConsulToken   string `mapstructure:"consul_token"`

	ProjectName    string `mapstructure:"project_name"`
	ProjectVersion string `mapstructure:"project_version"`
}

type PostProcessor struct {
	config Config
	client *api.Client
	auth   aws.Auth
}

func (p *PostProcessor) Configure(raws ...interface{}) error {
	if err := config.Decode(&p.config, nil, raws...); err != nil {
		return err
	}

	required := map[string]*string{
		"consul_address":  &p.config.ConsulAddress,
		"project_name":    &p.config.ProjectName,
		"project_version": &p.config.ProjectVersion,
	}

	errs := new(packer.MultiError)
	for key, ptr := range required {
		if *ptr == "" {
			errs = packer.MultiErrorAppend(
				errs, fmt.Errorf("%s must be set", key))
		}
	}

	if len(errs.Errors) > 0 {
		return errs
	}

	// https://github.com/mitchellh/goamz/blob/master/aws/aws.go#L313 will get the key and id from
	// instance profile if these settings are empty
	auth, err := aws.GetAuth(p.config.AwsAccessKey, p.config.AwsSecretKey)
	if err != nil {
		return err
	}
	p.auth = auth

	if p.config.AwsToken != "" {
		p.config.AwsToken = p.auth.Token
	}

	return nil
}

func (p *PostProcessor) PostProcess(ui packer.Ui, artifact packer.Artifact) (packer.Artifact, bool, error) {
	_, ok := supported[artifact.BuilderId()]
	if !ok {
		return nil, false, fmt.Errorf(
			"Unsupported artifact type: %s", artifact.BuilderId())
	}

	ui.Say("Putting build artifacts into consul: " + artifact.Id())

	for _, regions := range strings.Split(artifact.Id(), ",") {
		parts := strings.Split(regions, ":")
		if len(parts) != 2 {
			err := fmt.Errorf("Poorly formatted artifact ID: %s", artifact.Id())
			return nil, false, err
		}

		regionconn := ec2.New(p.auth, aws.Regions[parts[0]])
		ids := []string{parts[1]}
		images, err := regionconn.Images(ids, nil)
		if err != nil {
			return artifact, false, err
		}

		config := api.DefaultConfig()
		config.Address = p.config.ConsulAddress
		config.Datacenter = parts[0]

		if p.config.ConsulScheme != "" {
			config.Scheme = p.config.ConsulScheme
		}

		if p.config.ConsulToken != "" {
			config.Token = p.config.ConsulToken
		}

		client, err := api.NewClient(config)
		if err != nil {
			return artifact, false, err
		}

		kv := client.KV()
		consul_key_prefix := fmt.Sprintf("amis/%s/%s/%s", p.config.ProjectName, images.Images[0].RootDeviceType, p.config.ProjectVersion)

		ui.Message(fmt.Sprintf("Putting %s image data into consul key prefix %s in datacenter %s",
			parts[1], consul_key_prefix, config.Datacenter))

		consul_data_key := fmt.Sprintf("%s/data", consul_key_prefix)
		ami_data, _ := json.Marshal(images.Images)
		kv_ami_data := &api.KVPair{Key: consul_data_key, Value: ami_data}

		_, err = kv.Put(kv_ami_data, nil)
		if err != nil {
			return artifact, false, err
		}

		consul_ami_key := fmt.Sprintf("%s/ami", consul_key_prefix)

		kv_ami_id := &api.KVPair{Key: consul_ami_key, Value: []byte(parts[1])}
		_, err = kv.Put(kv_ami_id, nil)
		if err != nil {
			return artifact, false, err
		}
	}

	return artifact, true, nil
}
