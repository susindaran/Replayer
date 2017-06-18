Replayer
=======

Replayer is a configurable automation tool written in Python to perform Non-Functional Regression testing by replaying production load using Jmeter. Replayer uses ClusterShell and rsync to access the log files in the production machines and extract payloads, API paths and query parameters using regexes.

### Installation

Clone the repository and navigate to **Replayer** folder

```sh
$ cd Replayer
$ ./replayer.py
```

By default Replayer will look for a configuration file with the name ``replayer.conf`` if nothing is specified.

Or you can specify the path to the configuration file as follows
```sh
$ ./replayer.sh /path/to/conf.conf
```
#### Dependencies
Replayer requires [ClusterShell](http://clustershell.readthedocs.io/en/latest/install.html#distribution) to run.

For quick installation of ClusterShell, do it via pip as follows
```sh
$ pip install clustershell
```
It also uses [Jmeter](http://jmeter.apache.org/) to run the performance test.
## Usage

Replayer requires two things to function.
* A ``.jmx`` file - required for Jmeter
* A configuration file

The .jmx file can be prepared by using the [Jmeter](http://jmeter.apache.org/) tool. The idea is to create the basic settings required for your performance test through jmeter and provide it to Replayer.

For example, if you need a query parameter to be extracted from the production logs, you can configure the initial jmx file for a csv datasource. Through the Replayer's configuration file you can specify the names of the csv files which your jmx file is expecting and the query parameters that are to be extracted from the logs and populated in each csv file. Replayer will extract the needed data from the log files using the given regex patterns and will also extract the query parameters and populate the csv files.

> **Note:**
> Right now Replayer supports only one parameter per csv file.

### Configuration
Config Property name     | Description
-------- | ---
sourceHosts | List of hostnames from which the logs are to be extracted
targetHost    | Target host on which performance test is to be run
port     | Service port on the target host
logFilesPath | Path to the log files in the source hosts
logFilesNamePattern | A regex pattern for the name of the log files in the source hosts
requestPayloadPattern | A regex pattern using which data will be extracted from the log files
extractParameters | Reuest query parameters to be extracted from the payloads, if any
requestPath | The API path to be used for the performance test
requestMethod | API method
csvFileNames | Comma separated list of csv file name which are used in the sample jmx provided
jmx_FileName | Path to the provided jmx file
jmx_targetFileName | Name of the final jmx file to be produced by Replayer
jmx_numberOfThreads | Number of threads to spawn through Jmeter
jmx_rampUpPeriod | Ramp up period for Jmeter
jmx_loopForever | Boolean setting to either infinitely loop through the requests or not
jmx_loopCount | Number of times the requests should be looped through if jmx_loopForever is false
