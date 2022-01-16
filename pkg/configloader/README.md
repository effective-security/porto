configloaded
============

Installation
------------

```
go get github.com/effective-security/porto/pkg/configloader
```

Usage
-----

```go
	f, err := NewFactory(nil, []string{"/cfg/override_location"}, "MYSERVICE_")
	if err != nil {
        return err
    }

	var c configuration
	err = f.Load(cfgFile, &c)
	if err != nil {
        return err
    }
```

Environment variables
---------------------

The loader interpolates configuration values with the supported environment variables described below, and other OS Env variables that has prefix passed to `NewFactory`

- `${HOSTNAME}` : host name
- `${NODENAME}` : node name if the cluster
- `${LOCALIP}` : local IP address
- `${USER}` : user name under which the process is running
- `${NORMALIZED_USER}` : user name without dots
- `${ENVIRONMENT}` : environment name of the deployment, aka `test`,`dev`,`prod` etc
- `${ENVIRONMENT_UPPERCASE}` : environment name in upper case
- any environment variable started with `MYSERVICE_` prefix

Config override
---------------

The loader supports config overrides by host name, or with a provided file by `WithOverride` method.

If there is file named as the config file with `.hostmap` suffix, if will be loaded,
and override values will be applied to the main config file, based on the host name.

The format of the `.hostmap` file:

```yaml
override:
  HOSTNAME: override.yaml
```

See `testdata` folder for examples.