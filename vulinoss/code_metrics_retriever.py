import argparse
import pymysql as db_connector
import os
from colorama import Fore, Back, Style

from utility import Utility
from project import Project, ProjectList
from testing_code_analyzer import TestingCodeAnalyzer
from continous_integration_analyzer import ContinousIntegrationAnalyzer

# programming language mapping to id for database storing
language_list = {
    "ABAP":1,"ActionScript":2,"Ada":3,"ADSO/IDSM":4,"AMPLE":5,
    "Ant":6,"ANTLR Grammar":7,"Apex Trigger":8,"Arduino Sketch":9,"ASP":10,"ASP.Net":11,"AspectJ":12,
    "Assembly":13,"AutoHotkey":14,"awk":15,"Blade":16,"Bourne Again Shell":17,"Bourne Shell":18,
    "BrightScript":19,"builder":20,"C":21,"C Shell":22,"C#":23,"C++":24,'C/C++ Header':25,
    "CCS":26,"Chapel":27,"Clean":28,"Clojure":29,"ClojureC":30,"ClojureScript":31,
    "CMake":32,"COBOL":33,"CoffeeScript":34,"ColdFusion":35,"ColdFusion CFScript":36,
    "Coq":37,"Crystal":38,"CSON":39,"CSS":40,"Cucumber":41,"CUDA":42,"Cython":43,
    "D":44,"DAL":45,"Dart":46,"diff":47,"DITA":48,"DOORS Extension Language":49,"DOS Batch":50,"Drools":51,
    "DTD":52,"dtrace":53,"ECPP":54,"EEx":55,"Elixir":56,"Elm":57,"ERB":58,"Erlang":59,
    "Expect":60,"F#":61,"F# Script":62,"Focus":63,"Forth":64,"Fortran 77":65,"Fortran 90":66,
    "Fortran 95":67,"Freemarker Template":68,"GDScript":69,"Glade":70,"GLSL":71,"Go":72,
    "Grails":73,"GraphQL":74,"Groovy":75,"Haml":76,"Handlebars":77,"Harbour":78,
    "Haskell":79,"Haxe":80,"HLSL":81,"HTML":82,"IDL":83,"Idris":84,"INI":85,
    "InstallShield":86,"Java":87,"JavaScript":88,"JavaServer Faces":89,"JCL":90,"JSON":91,
    "JSP":92,"JSX":93,"Julia":94,"Kermit":95,"Korn Shell":96,"Kotlin":97,"LESS":98,
    "lex":99,"LFE":100,"liquid":101,"Lisp":102,"Literate Idris":103,"LiveLink OScript":104,
    "Logtalk":105,"Lua":106,"m4":107,"make":108,"Mako":109,"Markdown":110,
    "Mathematica":111,"MATLAB":112,"Maven":113,"Modula3":114,"MSBuild script":115,
    "MUMPS":116,"Mustache":117,"MXML":118,"NAnt script":119,"NASTRAN DMAP":120,"Nemerle":121,
    "Nim":122,"Objective C":123,"Objective C++":124,"OCaml":125,"OpenCL":126,"Oracle Forms":127,
    "Oracle Reports":128,"Pascal":129,"Pascal/Puppet":130,"Patran Command Language":131,"Perl":132,"PHP":133,
    "PHP/Pascal":134,"Pig":135,"PL/I":136,"PO File":137,"PowerBuilder":138,"PowerShell":139,
    "Prolog":140,"Protocol Buffers":141,"Pug":142,"PureScript":143,"Python":144,"QML":145,
    "Qt":146,"Qt Linguist":147,"Qt Project":148,"R":149,"Racket":150,"RapydScript":151,"Razor":152,
    "Rexx":153,"RobotFramework":154,"Ruby":155,"Ruby HTML":156,"Rust":157,"SAS":158,
    "Sass":159,"Scala":160,"Scheme":161,"sed":162,"SKILL":163,"SKILL++":164,
    "Slice":165,"Slim":166,"Smalltalk":167,"Smarty":168,"Softbridge Basic":169,
    "Solidity":170,"Specman e":171,"SQL":172,"SQL Data":173,"SQL Stored Procedure":174,"Standard ML":175,
    "Stata":176,"Stylus":177,"Swift":178,"Tcl/Tk":179,"Teamcenter met":180,
    "Teamcenter mth":181,"TeX":182,"TITAN Project File Information":183,"Titanium Style Sheet":184,"TOML":185,"TTCN":186,
    "Twig":187,"TypeScript":188,"Unity-Prefab":189,"Vala":190,"Vala":191,
    "Velocity Template Language":192,"Verilog-SystemVerilog":193,"VHDL":194,"vim script":195,"Visual Basic":196,
    "Visual Fox Pro":197,"Visualforce Component":198,"Visualforce Page":199,"Vuejs Component":200,"Windows Message File":201,
    "Windows Module Definition":202,"Windows Resource File":203,"WiX include":204,"WiX source":205,"WiX string localization":206,"XAML":207,"xBase":208,
    "xBase Header":209,"XHTML":210,"XMI":211,"XML":212,"XQuery":213,"XSD":214,"XSLT":215,
    "yacc":216,"YAML":217,"zsh":218,"Puppet":219
}

ci_providers = {
    "Travis":1,"AppVeyor":2,"Magnum":3,"Circle":4,"Hound":5,"Scrutinizer":6,
    "Shippable":7,"Solano":8,"Wercker":9
}

parser = argparse.ArgumentParser()
parser.add_argument("oss_list",
    help="The csv with the list of the projects to be retrieved from the database and analyzed")
parser.add_argument("repository_root_directory",
    help="The root directory that contains the downloaded repositories")
parser.add_argument("-w", "--write_to_file",
    help="The output csv file")
args = parser.parse_args()

project_list_csv_filepath = args.oss_list

def read_project_list_file(filepath, connection):
    project_list = ProjectList()
    cursor = connection.cursor()
    print("Reading project list from file {}".format(filepath))
    project_list_lines = [line.strip() for line in open(filepath, 'r')]
    for line in project_list_lines:
        fields = line.split(';')
        pvendor=fields[0].split(":")[0]
        pname=fields[0].split(":")[1]
        # get also repo_url, repo_type, cvs_type
        query = "SELECT id, repo_url, repo_type, has_version_mapping FROM project WHERE pvendor=%s AND pname=%s"
        cursor.execute(query, (pvendor, pname))
        connection.commit()
        result = cursor.fetchall()
        # print(result)
        prid = result[0][0]
        if prid:
            project = Project(prid,pvendor,pname)
            project.repo_url = result[0][1]
            project.repo_type = result[0][2]
            project.commit_reference = result[0][3]
            # print("Creating project ==> {},{}:{},{},{},{}".format(prid,pvendor,pname,project.repo_url,project.repo_type,project.commit_reference))
            query = "SELECT id, version_reference FROM vulinoss.project_releases where pid=%s"
            cursor.execute(query, (int(prid)))
            connection.commit()
            results = cursor.fetchall()
            for version in results:
                # print(version)
                project.versions_with_cves[version[0]]=version[1]
            # print("result::{}".format(result))
            project_list.add(project)
        else:
            print("##ERROR## Undifined id for {}:{}".format(pvendor,pname))

    return project_list


def match_local_to_repo(repo, repo_full_path, project_list):
    for project in project_list.projects:
        if project.repo_url.endswith(repo.replace("_", "/", 100)):
            project.local_repo_dir = repo_full_path.replace("\\","/",100)
            # print("\tFound match: {}::{}".format(project.repo_url,project.local_repo_dir)) #DEBUG
            return
    print(Fore.RED +"\t\tERROR : Didn't match to any of the NVD projects {}".format(repo) + Style.RESET_ALL)


def get_repositories(a_dir):
    return [repo for repo in os.listdir(a_dir)
        if os.path.isdir(os.path.join(a_dir, repo))]


def analyse_version(project, version_id, version_tag):
    print("Checking out {} tag:{} for project {}:{} in {}".format(
        project.repo_type,version_tag,project.name,project.vendor,project.local_repo_dir),
        flush=True)
    if project.repo_type == "git":
        command = "git -C {} checkout {}".format(project.local_repo_dir, version_tag)
    elif project.repo_type == "hg":
        command = "hg checkout -R {} {}".format(project.local_repo_dir, version_tag)
    elif project.repo_type == "svn":
        command = "svn update {} {}".format(version_tag, project.local_repo_dir)
        print("SVN command: {}".format(command))
    else:
        print("Checking out for non-git repos is not implemented yet", flush=True)
        return    

    # print("command: {}".format(command), flush=True)
    result = Utility.execute_process(command)

    # print("result: {}".format(result), flush=True)
    cloc_output = Utility.run_cloc(project.local_repo_dir)
    # print("CLOC:: {}".format(cloc_output))
    code_metrics = Utility.parse_cloc_output(cloc_output)
    # print(code_metrics)
    # print("Testing code analyzer::")
    testing_code_analyzer = TestingCodeAnalyzer(project)
    testing_code_metrics = testing_code_analyzer.analyze()
    # print("testing metrics:: {}".format(testing_code_metrics))

    #match code metrics to testing code metrics
    if testing_code_metrics:
        for test_lang in testing_code_metrics:
            if test_lang in code_metrics:
                for test_metric in testing_code_metrics[test_lang]:
                    code_metrics[test_lang].append(test_metric)

    # print("Identifying ContinousIntegration ")
    # ci analyzer
    continous_integration_analyzer = ContinousIntegrationAnalyzer(project)
    project.continuous_integration = continous_integration_analyzer.analyze()
    # print("code metrics with testing code:{}".format(code_metrics))
    # print(code_metrics)
    return code_metrics


def write_entry_to_csv(project, version_id, version_tag, code_metrics, csv_filepath):
    # print("Code metrics::{}".format(code_metrics))
    
    with open(csv_filepath, 'a') as output_file:
        # write project release CI update sql
        ci_entry = ""
        if project.continuous_integration:
            ci_entry = ci_providers[project.continuous_integration]
        update = (
                "UPDATE `vulinoss`.`project_releases` "
                "SET `continuous_integration`={} "
                "WHERE `id`={};"
        ).format(
            ci_entry,
            version_id
        )
        output_file.write("{}\n".format(update))
        # print("UPDATE::{}".format(update))

        for lang in code_metrics:
            if lang not in language_list:
                print("Skipping lang {}. not in list".format(lang))
                return
            # print(lang)
            # write code_metrics update
            size = code_metrics[lang][0]
            blank = code_metrics[lang][1]
            comment = code_metrics[lang][2]
            loc = code_metrics[lang][3]
            testing_size = 0
            testing_blank = 0
            testing_comment = 0
            testing_loc = 0

            # when version HAS testing metrics
            if len(code_metrics[lang]) > 4:
                testing_size = code_metrics[lang][4]
                testing_blank = code_metrics[lang][5]
                testing_comment = code_metrics[lang][6]
                testing_loc = code_metrics[lang][7]

            output_string = (
                "INSERT INTO `vulinoss`.`code_metrics` ("
                "prid," # project_release_id from table project_release
                "language_id," # programming language
                "size," # number of files written in this programming language
                "blank," # number of blank lines in the files
                "comment," # number of comment lines in the files
                "loc," # number of lines of code in the files
                "testing_size," # number of lines of code in the testing files
                "testing_blank," # number of lines of code in the testing files
                "testing_comment," # number of lines of code in the testing files
                "testing_loc" # number of lines of code in the testing files
                ") VALUES ("
                "{},"   # prid
                '{},'   # language
                "{},"   # size
                "{},"   # blank
                "{},"   # comment
                "{},"   # loc
                "{},"   # testing_size
                "{},"   # testing_blank
                "{},"   # testing_comment
                "{}"    # testing_loc
                ");"
            ).format(
                version_id,
                # language_list[lang.replace("\/","-")],
                language_list[lang],
                size,
                blank,
                comment,
                loc,
                testing_size,
                testing_blank,
                testing_comment,
                testing_loc
            )
            # for metric in code_metrics[lang]:
            #     output_string += "{},".format(metric) 

            # output_string = output_string.strip(',')

            # if len(code_metrics[lang]) < 8:
            #     output_string += "{},{},{},{}".format(0,0,0,0)
            # print("Language:{}".format(lang))
            # print("OUTPUT STRING:{}".format(output_string))
            output_file.write("{}\n".format(output_string))


connection = db_connector.connect(host='localhost',
                             user='root',
                             # password='mysql@d77c02',
                             password='',
                             db='vulinoss')

project_list = read_project_list_file(project_list_csv_filepath, connection)
local_repos_root_directory = args.repository_root_directory
print("Looking for projects in directory: %s" % local_repos_root_directory)
local_repos = get_repositories(local_repos_root_directory)
for repo in local_repos:
    repo_full_path = os.path.join(local_repos_root_directory, repo)
    # print("Checking if repo exists :: {}".format(repo_full_path))
    match_local_to_repo(repo, repo_full_path, project_list)

for project in project_list.projects:
    if project.local_repo_dir and project.commit_reference != "-":# and project.name == "w3m":
        print("PROJECT::{}".format(project.name))
        for version in project.versions_with_cves:
            if project.versions_with_cves[version]:
                # print("Project: {}, version: {}".format(project.name,project.versions_with_cves[version]))
                code_metrics = analyse_version(project, version, project.versions_with_cves[version])
                if code_metrics is not None:
                    
                    if args.write_to_file:
                        write_entry_to_csv(project, version, project.versions_with_cves[version], code_metrics, args.write_to_file)
                else:    
                    print("Version skipped. CLOC results not valid")
        # project.print()


# project_list.print()
