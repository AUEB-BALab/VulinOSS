import subprocess
import os
from tempfile import NamedTemporaryFile
from colorama import Fore, Back, Style

class Utility(object):
    log_file = "error_log.txt"

    @staticmethod
    def write_exception_to_log(project_name, exception):
        with open(Utility.log_file, 'a') as log:
            log.write("Project :: {}\n\tException :: {}\n".format(project_name, exception))


    @staticmethod
    def write_to_file(file_path, content):
        print("\tWriting project results to csv file: %s" % file_path)
        try:
            with open(file_path, 'a') as out_file:
                out_file.write(content)
        except Exception as e:
            Utility.write_exception_to_log(file_path, e)
            print("## Error when writting to %s" % file_path)


    @staticmethod
    def run_cloc(repo_path, filelist=False):
        # print("\tRunning CLOC tool...") # DEBUG
        command = 'perl ../lib/cloc.pl --csv '

        if filelist:
            # Using temporary file to overcome the character limit in bash
            tempfile = NamedTemporaryFile(delete=False)
            with open(tempfile.name,'w',encoding='utf-8') as _tempfile:
                for _file in filelist:
                    try:
                        _tempfile.write('{0}\n'.format(_file))
                    except Exception as e:
                        print(Fore.RED +"\t\t\tEncoding error in testing file. skipped." + Style.RESET_ALL) # DEBUG
                        print("Exception2:: %s" % e)
                        Utility.write_exception_to_log(repo_path, e)
                        pass
            command += '--list-file={0}'.format(tempfile.name)
        else:
            command += repo_path

        # print(command) #DEBUG
        # with open(Utility.log_file, 'a') as log:
        try:
            process = subprocess.Popen(
                command, shell=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
                # stdout=subprocess.PIPE, stderr=log
            )

            (out, err) = [x.decode() for x in process.communicate()]
        except Exception as e:
            print("Exception::CLOC:: %s" % e)
            Utility.write_exception_to_log(repo_path, e)

        return out


    @staticmethod
    def parse_cloc_output(cloc_output):
        # print(cloc_output) # angor
	# crop output
        start = "files,language,blank,comment,code"
        # in case that the cloc ignores all selected files
        if start not in cloc_output:
            print("CLOC output not valid")
            return None

        cloc_output = cloc_output[cloc_output.index(start):].split("\n")[1:]

        # Creating a dictionary with the language and its metrics
        lang_metrics = {}
        for line in cloc_output:
            cloc_metrics = line.split(",")
            if len(cloc_metrics) == 5:       
                lang = cloc_metrics[1]
                lang_metrics[lang] = [
                    int(cloc_metrics[0]),
                    int(cloc_metrics[2]),
                    int(cloc_metrics[3]),
                    int(cloc_metrics[4])]
                # print(lang_metrics) # DEBUG
            else:
                # print("Invalid cloc line --> %s" % cloc_metrics) # DEBUG
                pass

        return lang_metrics


    @staticmethod
    def execute_process(command):
        command = command.replace("\\","/")
        # print("\tExecuting process from command : {}".format(command)) # DEBUG

        try:
            # os.system(command)
            process = subprocess.Popen(
                command, shell=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
                # stdout=subprocess.PIPE, stderr=log
            )

            (out, err) = [x.decode() for x in process.communicate()]

        except Exception as e:
            print("Exception::execute_process::{}\n{}".format(command,e))
            Utility.write_exception_to_log(repo_path, e)

        # print(err)
        return out


    @staticmethod
    def run_gocloc(repo_path, filelist=False):
        print("\tRunning GoCLOC tool...") # DEBUG
        command = 'gocloc '
        command += repo_path

        print(command) #DEBUG
        # with open(Utility.log_file, 'a') as log:
        try:
            process = subprocess.Popen(
                command, shell=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
                # stdout=subprocess.PIPE, stderr=log
            )

            (out, err) = [x.decode() for x in process.communicate()]
        except Exception as e:
            print("Exception::run_gocloc:: %s" % e)
            Utility.write_exception_to_log(repo_path, e)

        return out