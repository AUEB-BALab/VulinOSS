class ProjectList(object):
    def __init__(self):
        self.projects = []
        print("ProjectList object created")


    def projectInList(self, vendor, name):
        for project in self.projects:
            if project.vendor == vendor and project.name == name:
                # print("Project {}:{} already exists".format(vendor, name))
                return True

        return False


    def get(self, vendor, name):
        for project in self.projects:
            if project.vendor == vendor and project.name == name:
                return project

        return None


    def add(self, project):
        self.projects.append(project)
        # print("@ProjectList :: added new project ({}:{})".format(project.vendor,project.name))


    def print(self):
        for project in self.projects:
            project.print()


    def insertIntoDB(self,db,cursor):
        print("Storing projects to database...", flush=True)
        for project in self.projects:
            project.storeProjectToDB(db,cursor)
           


class Project(object):
    software_types = {
        "Accessibility":1,"Audio":2,"Deskutils":3,"Editors":4,"Finance":5,
        "Games":6,"Graphics":7,"Multimedia":8,"Net-p2p":9,"Print":10,
        "Shells":11,"Textproc":12,"Ports":13,"Archivers":14,"Databases":15,
        "Devel":16,"Emulators":17,"Ports-mgmt":18,"Security":19,
        "Sysutils":20,"Ports":21,"Comms":22,"Dns":23,"Ftp":24,"Irc":25,
        "Mail":26,"Net":27,"Net-im":28,"Net-mgmt":29,"News":30,"Www":31,
        "Astro":32,"Biology":33,"Cad":34,"Math":35,"Science":36,
        "Programming-languages":37,"Benchmarks":38,"Converters":39,"Misc":40}

    def __init__(self, pid, vendor, name):
        self.id = pid
        self.vendor = vendor
        self.name = name
        self.software_type = ""
        self.website = ""
        self.repo_url = "" 
        self.repo_type = ""
        self.commit_reference = ""
        self.versions_with_cves = {}
        self.vulnerable_versions = {}

        #local repository link
        self.local_repo_dir = None
        
        # Each key (vulnerable version id) will store a list
        # of code metrics (Language, size, blank, comments, loc, testing metrics, etc)
        self.code_metrics = {}
        self.continuous_integration = ""


    def addVulnerability(self, version, cve):
        if version not in self.versions_with_cves:
            self.versions_with_cves[version] = []

        self.versions_with_cves[version].append(cve)


    def print(self):
        print("Project ID: {}".format(self.id))
        print("\tVendor: {}".format(self.vendor))
        print("\tName: {}".format(self.name))
        print("\tSoftware type: {}".format(self.software_type))
        print("\tWebsite: {}".format(self.website))
        print("\tRepo url: {}".format(self.repo_url))
        print("\tRepo type: {}".format(self.repo_type))
        print("\tCommit reference: {}".format(self.commit_reference))
        print("\tLocal path: {}".format(self.local_repo_dir))
        print("\tContinuous integration: {}".format(self.continuous_integration))


    def printShort(self):
        print("{}:{}".format(self.vendor,self.name))


    def storeProjectToDB(self, db, cursor):
        has_version_mapping = False
        if self.commit_reference == 'tag' or self.commit_reference == 'branch':
            has_version_mapping = True
        insert = (
            "INSERT INTO project ("
            # general attributes
            "id,"
            "pvendor,"
            "pname,"
            "software_type,"
            "website,"
            "repo_url,"
            "repo_type,"
            "has_version_mapping"
        ") VALUES ("
        "'{}'," # id
        "'{}'," # pvendor
        "'{}'," # pname
        "{},"  # software type
        "'{}'," # website url
        "'{}',"  # repo url
        "'{}',"  # repo type
        "{}"  # has version mapping
        ")"
        ).format(
            self.id,
            self.vendor,
            self.name,
            # Project.software_types[self.software_type],
            40, # remove this line after manually assign project types
            self.website,
            self.repo_url,
            self.repo_type,
            has_version_mapping
        )

        try:
            cursor.execute(insert)
            db.commit()
            # # data = cursor.fetchone()
        except (db.Error, db.Warning) as e:
            print(e)    
            print(insert)

        version_counter = 0
        for version in self.versions_with_cves:
            version_counter += 1
            self.storeVulnerableVersion(version, version_counter, db, cursor)


    def storeVulnerableVersion(self, version, version_counter, db, cursor):
        pv_id = "{}{}".format(self.id,str(version_counter).zfill(4))
        commit_tag = ""
        if version in self.vulnerable_versions:
            commit_tag = self.vulnerable_versions[version]
        none_value = None
        # Store the vulnerable version
        insert = (
                "INSERT INTO project_releases ("
                "id,"
                "version_name,"
                "pid,"
                "version_reference"
            ") VALUES ("
                "'{}'," # id (incremented in this function)
                "'{}'," # version
                "'{}'," # the  id of the project they belong in
                "'{}'" # the cvs commit reference
                ")"
            ).format(
                pv_id,
                version,
                self.id,
                commit_tag
            )
        try:
            cursor.execute(insert)
            db.commit()
        except (db.Error, db.Warning) as e:
            print(e)
            print(insert)


        # print("Storing cves for {} {}".format(self.name, version))
        # Store the exploits (vulnearble version with CVE)
        # for cve in self.versions_with_cves[version]:
        #     insert = (
        #         "INSERT INTO vulnerable_cases ("
        #             "cve,"
        #             "prid"
        #         ") VALUES ("
        #             "'{}'," # cve
        #             "{}" # id (incremented in this function)
        #             ")"
        #         ).format(
        #             cve,
        #             pv_id
        #         )
        #     try:
        #             cursor.execute(insert)
        #             db.commit()
        #     except (db.Error, db.Warning) as e:
        #             print(e)
        #             print(insert)
