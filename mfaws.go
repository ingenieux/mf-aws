package mfaws

import (
	"fmt"
	"github.com/avast/retry-go"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/creachadair/otp/otpauth"
	"github.com/ingenieux/mf-aws/util"
	"github.com/joomcode/errorx"
	"github.com/mitchellh/go-homedir"
	"github.com/pquerna/otp/totp"
	"gopkg.in/ini.v1"
	"io"
	"os"
	"strings"
	"time"
)

const MfaConfigPath = "~/.aws/mf-aws.ini"

var region = util.EnvIf("AWS_DEFAULT_REGION", "AWS_REGION", "us-east-1")

type MFEngine struct {
	profile            string
	output             io.Writer
	tokenArn           string
	keyUrl             *otpauth.URL
	stsClient          *sts.STS
	sessionTokenOutput *sts.GetSessionTokenOutput
}

func NewMFEngine(profile string) (*MFEngine, error) {
	return &MFEngine{
		profile: profile,
		output:  os.Stdout,
	}, nil
}

func (e *MFEngine) Execute() error {
	err := e.loadConfig()

	if nil != err {
		return errorx.Decorate(err, "loading config (profile: %s)", e.profile)
	}

	err = e.getSessionToken()

	if nil != err {
		return errorx.Decorate(err, "obtaining session token")
	}

	err = e.outputCredentials()

	if nil != err {
		return errorx.Decorate(err, "writing credentials")
	}

	return err
}

func (e *MFEngine) loadConfig() error {
	configPath, err := homedir.Expand(MfaConfigPath)

	if nil != err {
		return errorx.Decorate(err, "looking up home at %s", MfaConfigPath)
	}

	iniFile, err := ini.Load(configPath)

	if nil != err {
		return errorx.Decorate(err, "parsing ini file at %s", configPath)
	}

	section, err := iniFile.GetSection(e.profile)

	if nil != err {
		return errorx.Decorate(err, "looking up section at %s", configPath)
	}

	for _, k := range []string{"mfa-arn", "mfa-key"} {
		if value := section.Key(k); nil == value {
			return fmt.Errorf("missing key '%s' in config file '%s' for profile '%s'", k, configPath, e.profile)
		}
	}

	arn := section.Key("mfa-arn")

	e.tokenArn = arn.String()

	mfaKey := section.Key("mfa-key")

	keyUrl, err := otpauth.ParseURL(mfaKey.String())

	if nil != err {
		return errorx.Decorate(err, "parsing otpauth url '%s'", mfaKey.String())
	}

	e.keyUrl = keyUrl

	sess, err := e.getSession()

	if nil != err {
		return errorx.Decorate(err, "creating aws session")
	}

	stsClient := sts.New(sess, aws.NewConfig().WithRegion(region))

	_, err = stsClient.GetCallerIdentity(&sts.GetCallerIdentityInput{})

	if nil != err {
		return errorx.Decorate(err, "trying to fetch identity")
	}

	e.stsClient = stsClient

	return nil
}

func (e *MFEngine) getSession() (*session.Session, error) {
	return session.NewSessionWithOptions(session.Options{
		Config: aws.Config{
			Region:      aws.String(region),
			Credentials: credentials.NewSharedCredentials("", e.profile),
		},
	})
}

func (e *MFEngine) getSessionToken() error {
	var sessionTokenOutput *sts.GetSessionTokenOutput

	err := retry.Do(func() (err error) {
		code, err := totp.GenerateCode(e.keyUrl.RawSecret, time.Now())

		if nil != err {
			err = errorx.Decorate(err, "generating totp code")

			return
		}

		sessionTokenOutput, err = e.stsClient.GetSessionToken(&sts.GetSessionTokenInput{
			//DurationSeconds: aws.Int64(1800),
			SerialNumber: aws.String(e.tokenArn),
			TokenCode:    aws.String(code),
		})

		if nil != err {
			err = errorx.Decorate(err, "obtaining session token")
		}

		return
	}, retry.Attempts(2), retry.Delay(1*time.Second))

	if nil != err {
		return err
	}

	e.sessionTokenOutput = sessionTokenOutput

	return nil
}

func (e *MFEngine) outputCredentials() error {
	err := e.writeDisableStatements()

	if nil != err {
		return err
	}

	nvPairs := make(map[string]string)

	nvPairs["AWS_ACCESS_KEY_ID"] = *e.sessionTokenOutput.Credentials.AccessKeyId
	nvPairs["AWS_SECRET_ACCESS_KEY"] = *e.sessionTokenOutput.Credentials.SecretAccessKey
	nvPairs["AWS_SESSION_TOKEN"] = *e.sessionTokenOutput.Credentials.SessionToken
	nvPairs["AWS_TOKEN_EXPIRATION"] = fmt.Sprintf("%d", e.sessionTokenOutput.Credentials.Expiration.Unix())

	nvStatements := make([]string, 0)

	for k, v := range nvPairs {
		nvStatements = append(nvStatements, fmt.Sprintf("%s='%s'", k, v))
	}

	joinedStatementsToSet := strings.Join(nvStatements, " ")

	exportStatement := fmt.Sprintf("export %s\n", joinedStatementsToSet)

	_, err = e.output.Write([]byte(exportStatement))

	if nil != err {
		return errorx.Decorate(err, "writing statements for credentials")
	}

	return nil
}

func (e *MFEngine) writeDisableStatements() error {
	forbiddenVars := []string{"AWS_ACCESS_KEY_ID", "AWS_PROFILE", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_TOKEN_EXPIRATION"}

	varsToDelete := make([]string, 0)

	for _, envVar := range forbiddenVars {
		if _, exists := os.LookupEnv(envVar); exists {
			varsToDelete = append(varsToDelete, envVar)
		}
	}

	if 0 != len(varsToDelete) {
		_, err := e.output.Write([]byte(fmt.Sprintf("unset %s\n", strings.Join(varsToDelete, " "))))

		if nil != err {
			return errorx.Decorate(err, "writing statements to delete")
		}
	}

	return nil
}
