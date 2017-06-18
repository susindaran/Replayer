from optparse import OptionParser
from xml.dom import minidom
import xml.etree.ElementTree as elementTree
import ConfigParser
import sys
import logging
import csv
import time
import gzip
import glob
import os.path

from ClusterShell.Task import task_self
from ClusterShell.Event import EventHandler
from ClusterShell.NodeSet import NodeSet


class Colors:

	def __init__(self):
		pass

	HEADER = '\033[95m'
	BLUE = '\033[94m'
	GREEN = '\033[92m'
	WARNING = '\033[93m'
	FAIL = '\033[91m'
	ENDC = '\033[0m'
	BOLD = '\033[1m'
	UNDERLINE = '\033[4m'


class CustomLogger:

	ERROR = 1
	WARN = 2
	INFO = 3
	DEBUG = 4

	def __init__(self, level):
		self.level = level

	def error(self, message):
		if self.level >= self.ERROR:
			self.color_print(message, Colors.FAIL)
			logging.error(message.replace("\n", ""))

	def warn(self, message):
		if self.level >= self.WARN:
			self.color_print(message, Colors.WARNING)
			logging.warn(message.replace("\n", ""))

	def info(self, message):
		if self.level >= self.INFO:
			self.color_print(message, Colors.GREEN)
			logging.info(message.replace("\n", ""))

	def debug(self, message):
		if self.level >= self.DEBUG:
			self.color_print(message, Colors.BLUE)
			logging.debug(message.replace("\n", ""))

	@staticmethod
	def color_print(message, color):
		sys.stdout.write("{0}{1}{2}".format(color, message, Colors.ENDC))


class Configuration:

	def __init__(self, config_file_path):
		config_parser = ConfigParser.RawConfigParser()
		config_parser.read(config_file_path)

		self.source_hosts = config_parser.get('hostConfig', 'sourceHosts').strip().split(",")
		self.target_host = config_parser.get('hostConfig', 'targetHost').strip()
		self.port = config_parser.get('hostConfig', 'port').strip()
		self.log_files_path = config_parser.get('payloadConfig', 'logFilesPath').strip()
		self.log_files_name_patterns = config_parser.get('payloadConfig', 'logFilesNamePattern').strip().split("\x01")
		self.request_payload_patterns = config_parser.get('payloadConfig', 'requestPayloadPattern').strip().split("\x01")
		self.request_path = config_parser.get('payloadConfig', 'requestPath').strip()
		self.request_method = config_parser.get('payloadConfig', 'requestMethod').strip()
		self.extract_parameters = config_parser.get('payloadConfig', 'extractParameters').strip().split(",")
		self.csv_file_names = config_parser.get('payloadConfig', 'csvFileNames').strip().split(",")
		self.jmx_file_name = config_parser.get('jmeterConfig', 'jmx_FileName').strip()
		self.jmx_target_file_name = config_parser.get('jmeterConfig', 'jmx_targetFileName').strip()
		self.jmx_number_of_threads = config_parser.get('jmeterConfig', 'jmx_numberOfThreads').strip()
		self.jmx_ramp_up_period = config_parser.get('jmeterConfig', 'jmx_rampUpPeriod').strip()
		self.jmx_loop_forever = config_parser.get('jmeterConfig', 'jmx_loopForever').strip()
		self.jmx_loop_count = config_parser.get('jmeterConfig', 'jmx_loopCount').strip()
		self.jxm_bin_path = config_parser.get('jmeterConfig', 'jmx_binPath').strip()


class HostCheckHandler(EventHandler):
	def ev_read(self, worker):
		buf = worker.current_msg
		if "Could not resolve hostname" in buf:
			replayer.logger.error(worker.current_node + " - " + worker.current_msg)
			sys.exit("\nHost connection error!\n")
		else:
			replayer.logger.debug("\n" + worker.current_node + " - " + worker.current_msg + "\n")


class MkdirHandler(EventHandler):
	def ev_read(self, worker):
		buf = worker.current_msg
		if not buf:
			replayer.logger.debug("Created Directory : " + str(replayer.current_node))


class LsLogsHandler(EventHandler):
	def ev_read(self, worker):
		buf = worker.current_msg
		replayer.local_logs.append(replayer.current_node + "/" + buf)

	def ev_error(self, worker):
		replayer.logger.error("\nSomething went wrong. Check the log file (replayer.log)\n")


class RsyncHandler(EventHandler):
	def ev_read(self, worker):
		replayer.logger.debug('{}\r'.format(worker.current_msg))

	def ev_error(self, worker):
		replayer.logger.error("\nSomething went wrong. Check the log file (replayer.log)\n")


class GrepPayloadHandler(EventHandler):
	def ev_read(self, worker):
		buf = worker.current_msg
		replayer.payloads.append(buf)

	def ev_error(self, worker):
		replayer.logger.error("\nSomething went wrong. Check the log file (replayer.log)\n")


class JmeterHandler(EventHandler):
	def ev_read(self, worker):
		buf = worker.current_msg
		replayer.logger.debug("\t" + buf + "\n")

	def ev_error(self, worker):
		replayer.logger.error("\nSomething went wrong. Check the log file (replayer.log)\n")


class Replayer:

	def __init__(self):
		logging.basicConfig(filename = './logs/replayer.log', filemode = 'w', level = logging.DEBUG)

		parser = OptionParser()
		parser.add_option("-c", "--config", action = "store", dest = "configFilePath", default = "replayer.conf",
																				help = "Configuration File")
		parser.add_option("-v", "--verbose", action = "store_true", dest = "verbose", default = False,
																				help = "Verbose output of the tool")

		(options, args) = parser.parse_args()

		if options.verbose:
			self.logger = CustomLogger(CustomLogger.DEBUG)
		else:
			self.logger = CustomLogger(CustomLogger.INFO)

		CustomLogger.color_print("\n\nReading configuration file...\n", Colors.BOLD + Colors.UNDERLINE)

		self.config = Configuration(options.configFilePath)
		self.current_node = ""
		self.local_logs = []
		self.payloads = []
		self.task = task_self()

	def get_config_value(self, key_name):
		return {
			'HTTPSampler.domain': self.config.target_host,
			'HTTPSampler.port': self.config.port,
			'HTTPSampler.method': self.config.request_method,
			'HTTPSampler.path': self.config.request_path,
			'ThreadGroup.num_threads': self.config.jmx_number_of_threads,
			'ThreadGroup.ramp_time': self.config.jmx_ramp_up_period,
			'LoopController.loops': self.config.jmx_loop_count
		}.get(key_name)

	def print_banner(self):
		self.logger.info("\n    ____             __                     ")
		self.logger.info("\n   / __ \\___  ____  / /___ ___  _____  _____")
		self.logger.info("\n  / /_/ / _ \\/ __ \\/ / __ `/ / / / _ \\/ ___/")
		self.logger.info("\n / _, _/  __/ /_/ / / /_/ / /_/ /  __/ /    ")
		self.logger.info("\n/_/ |_|\\___/ .___/_/\\__,_/\\__, /\\___/_/     ")
		self.logger.info("\n           /_/            /____/        Jmeter Integrated\n\n")

	def sync_files(self, nodeset, pwd):
		# SYNCING FILES
		# rsync -rv --progress --include='*root*' --include='*/' --exclude='*' host:path local_path

		self.logger.warn("\nSyncing files... Might take a while, please wait...\n")
		sys.stdout.flush()

		for node in nodeset:
			for logFilesNamePattern in self.config.log_files_name_patterns:
				rsync_command = "rsync -rv --delete --progress --include='*" + logFilesNamePattern + \
							"*' --include='*/' --exclude='*' " + node + ":" + self.config.log_files_path + " " + pwd + "/" + node
				self.task.run(rsync_command, handler = RsyncHandler())

		self.logger.info("[COMPLETED]\n")

	def extract_zip_files(self, nodeset):
		self.logger.warn("\nExtracting ZIP Files...")
		for node in nodeset:
			for gzip_path in glob.glob(node + "/*.gz"):
				if not os.path.isdir(gzip_path):
					in_file = gzip.open(gzip_path, 'rb')

					# uncompress the gzip_path INTO THE 'content' variable
					content = in_file.read()
					in_file.close()

					# get gzip filename (without directories)
					gzip_file_name = os.path.basename(gzip_path)

					# get original filename (remove the file extensions from the end - .tar.gz)
					gzip_file_name = gzip_file_name[:gzip_file_name.rfind(".")]
					file_name = gzip_file_name[:gzip_file_name.rfind(".")]
					uncompressed_path = os.path.join(node + "/", file_name)

					# store uncompressed file data from 'content' variable
					open(uncompressed_path, 'w').write(content)
					self.logger.debug("\n\tCreated file : " + str(uncompressed_path) + "\n")

		self.logger.info("[COMPLETED]\n")

	def extract_parameters_from_logs(self, nodeset):
		self.local_logs = []
		for node in nodeset:
			self.current_node = node
			for logFilesNamePattern in self.config.log_files_name_patterns:
				command = "ls " + node + "/ | grep " + logFilesNamePattern + " | grep -v \'\.tar.gz\'"
				self.task.run(command, handler = LsLogsHandler())

		number_of_files = len(self.local_logs)
		self.logger.debug("\nNumber of log files present locally(After Syncing) : " + str(number_of_files) + "\n")

		# Extracting the payload from logs
		end = 0
		flag = False

		self.logger.debug("\nRequest paths : " + str(self.config.request_path) + "\n")
		self.logger.info("\nExtracting parameters from logs and building required CSV File(s)...\n")
		csv_writers = []
		for fileName in self.config.csv_file_names:
			csv_file = open(fileName, 'w')
			field_names = ['field1']
			writer = csv.DictWriter(csv_file, field_names)
			csv_writers.append(writer)

		while not flag:
			start = end
			end += 2
			local_log_files = []
			if end > number_of_files:
				end = number_of_files
				flag = True

			self.logger.debug("\tExtracting from Log Files : " + str(start) + " - " + str(end))

			for i in range(start, end):
				local_log_files.append(self.local_logs[i])

			self.logger.debug("Check - " + str(local_log_files) + "\n")
			self.task.set_info('debug', False)

			temp_count = 0
			for log in local_log_files:
				for requestPayloadPattern in self.config.request_payload_patterns:
					local_command = "grep " + requestPayloadPattern + " " + log
					self.task.run(local_command, handler = GrepPayloadHandler())

				self.logger.debug(
					"Number of payloads in file " + log + " : " + str(len(self.payloads) - temp_count) + "\n")
				temp_count = len(self.payloads)

			self.task.set_info('debug', True)

			field_arrays = [[] for x in range(len(self.config.extract_parameters))]
			for payload in self.payloads:
				index = 0
				for extractParameter in self.config.extract_parameters:
					field = payload[payload.find(extractParameter):len(payload)]
					field = field[field.find(extractParameter) + int(len(extractParameter) + 1):field.find("&")]
					field_arrays[index].append(field)
					index += 1

			for index in range(len(self.config.extract_parameters)):
				for value in field_arrays[index]:
					csv_writers[index].writerow({'field1': value})

		self.logger.info("\n[COMPLETED]")

	def prepare_and_execute_jmeter(self):
		# Preparing the .jmx file
		# Changing Host, path, port and method in JMX File
		self.logger.info("\n\nPreparing .jmx file...")

		tree = elementTree.parse(self.config.jmx_file_name)
		root = tree.getroot()

		for stringProp in root.iter('stringProp'):
			stringProp.text = self.get_config_value(stringProp.get('name'))
			self.logger.debug("\tChanged -> " + stringProp.get('name') + " : " + stringProp.text)

		for boolProp in root.iter('boolProp'):
			if boolProp.get('name') == 'LoopController.continue_forever':
				boolProp.text = self.config.jmx_loop_forever
				self.logger.debug("\tChanged -> " + boolProp.get('name') + " : " + boolProp.text)

		result_files = []

		for ResultCollector in root.iter('ResultCollector'):
			if ResultCollector.get('testname') == 'View Results Tree':
				for stringProp in ResultCollector.findall('stringProp'):
					if stringProp.get('name') == 'filename':
						f1 = "./results/" + str(int(time.time())) + "-results_tree.jtl"
						result_files.append(f1)
						stringProp.text = f1
						self.logger.debug("\tChanged -> " + stringProp.get('name') + " : " + stringProp.text)
			elif ResultCollector.get('testname') == 'Aggregate Report':
				for stringProp in ResultCollector.findall('stringProp'):
					if stringProp.get('name') == 'filename':
						f2 = "./results/" + str(int(time.time())) + "-agg_report.jtl"
						result_files.append(f2)
						stringProp.text = f2
						self.logger.debug("\tChanged -> " + stringProp.get('name') + " : " + stringProp.text)

		f = open(self.config.jmx_target_file_name, 'w')
		f.write(minidom.parseString(elementTree.tostring(root)).toprettyxml())
		f.close()

		self.logger.info("[COMPLETED]\n")

		def print_jmeter_debug(t, s):
			logging.debug("Task Debug : " + s)
			sys.stdout.write(Colors.BOLD + "\t" + s + "\n" + Colors.ENDC)
		self.task.set_info("print_debug", print_jmeter_debug)

		self.logger.info("\nStarting Jmeter...\n")

		jmeter_command = self.config.jxm_bin_path + "jmeter.sh -n -t " + self.config.jmx_target_file_name \
			+ " -j ./logs/jmeter.log"
		self.task.run(jmeter_command, Handler = JmeterHandler())
		self.logger.info("[COMPLETED]\n")
		self.logger.info("\nResults are available in : " + result_files[0] + " & " + result_files[1] + "\n")

	def run(self):
		self.print_banner()

		self.logger.debug("\nSource Hosts : " + str(self.config.source_hosts) + "\n")
		self.logger.debug("Target Host : " + str(self.config.target_host) + "\n")

		def print_cs_debug(t, s):
			logging.debug("Task Debug : " + s)

		# Creating Task
		self.task.set_info('debug', True)
		self.task.set_info("print_debug", print_cs_debug)

		# Assigning shell command to task
		nodeset = NodeSet()
		for sourceHost in self.config.source_hosts:
			nodeset.add(sourceHost)

		self.task.run("/bin/uname -r", nodes = nodeset, handler = HostCheckHandler())

		# Getting pwd
		pwd_worker = self.task.shell("pwd")
		self.task.resume()
		pwd = pwd_worker.current_msg
		self.logger.info("\nPresent working directory : " + pwd + "\n")

		# Creating Directories if not present already
		for node in nodeset:
			self.current_node = node
			mkdir_command = "mkdir " + str(node)
			self.task.run(mkdir_command, handler = MkdirHandler())

		# Getting local files
		for node in nodeset:
			self.current_node = node
			for logFilesNamePattern in self.config.log_files_name_patterns:
				command = "ls " + node + "/ | grep " + logFilesNamePattern + " | grep -v \'\.tar.gz\'"
				self.task.run(command, handler = LsLogsHandler())
		self.logger.info("\nLocal Files -> " + str(len(self.local_logs)) + "\n")

		self.sync_files(nodeset, pwd)
		self.extract_zip_files(nodeset)
		self.extract_parameters_from_logs(nodeset)
		self.prepare_and_execute_jmeter()

if __name__ == '__main__':
	replayer = Replayer()
	replayer.run()
