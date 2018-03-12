import os
import pymysql as db_connector
import argparse


def getInsertStatement(cwe,cwe_list):
    insert = (
                "INSERT INTO `vulinoss`.`cwe` ("
                "cwe,"
                "name,"
                "description"
            ") VALUES ("
                '"CWE-{}",' # the cwe id
                '"{}",' # name
                '"{}"' # short description
                ");"
            ).format(
                cwe,
                cwe_list[cwe][0].replace("'","",1000).replace('"',"",1000),
                cwe_list[cwe][3].replace("'","",1000).replace('"',"",1000)
            )
    return insert


parser = argparse.ArgumentParser()
parser.add_argument("cwe_input_csv",
    help="The csv that contains the complete cwe information")
parser.add_argument("-w", "--write_to_db", action="store_true",
    help="Flag for writting at the databse")
parser.add_argument("-p", "--print", action="store_true",
    help="Print generated sql statements")

args = parser.parse_args()
# print(args)

cwe_cvs_filepath = args.cwe_input_csv
cwe_lines = [line.strip() for line in open(cwe_cvs_filepath, 'r')]
cwe_list = {}
for line in cwe_lines:
    fields = line.split(',')
    cwe_list[fields[0]] = fields[1:]
    # print(fields)

if args.print:
    for cwe in cwe_list:
        insert = getInsertStatement(cwe,cwe_list)
        print(insert) 

if args.write_to_db:
    db = db_connector.connect(host= "localhost",
                  user="root",
                  passwd="",
                  db="vulinoss")
    cursor = db.cursor()
    print("Storing CVEs to database", flush=True)
    # Storing CVEs to DB
    for cwe in cwe_list:
        insert = getInsertStatement(cwe,cwe_list)
        # print(insert) 
        try:
            cursor.execute(insert)
            db.commit()
            # # data = cursor.fetchone()
        except (MySQLdb.Error, MySQLdb.Warning) as e:
            print(e)    
            print(insert)


