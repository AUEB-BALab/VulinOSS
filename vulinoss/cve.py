"""Base class for all cve entries"""

class CVE(object):

    cwes = ["CWE-1004","CWE-1007","CWE-102","CWE-1021",
    "CWE-1022","CWE-103","CWE-104","CWE-105","CWE-106",
    "CWE-107","CWE-108","CWE-109","CWE-11","CWE-110",
    "CWE-111","CWE-112","CWE-113","CWE-114","CWE-115",
    "CWE-116","CWE-117","CWE-118","CWE-119","CWE-12",
    "CWE-120","CWE-121","CWE-122","CWE-123","CWE-124",
    "CWE-125","CWE-126","CWE-127","CWE-128","CWE-129",
    "CWE-13","CWE-130","CWE-131","CWE-134","CWE-135",
    "CWE-138","CWE-14","CWE-140","CWE-141","CWE-142",
    "CWE-143","CWE-144","CWE-145","CWE-146","CWE-147",
    "CWE-148","CWE-149","CWE-15","CWE-150","CWE-151",
    "CWE-152","CWE-153","CWE-154","CWE-155","CWE-156",
    "CWE-157","CWE-158","CWE-159","CWE-160","CWE-161",
    "CWE-162","CWE-163","CWE-164","CWE-165","CWE-166",
    "CWE-167","CWE-168","CWE-170","CWE-172","CWE-173",
    "CWE-174","CWE-175","CWE-176","CWE-177","CWE-178",
    "CWE-179","CWE-180","CWE-181","CWE-182","CWE-183",
    "CWE-184","CWE-185","CWE-186","CWE-187","CWE-188",
    "CWE-190","CWE-191","CWE-192","CWE-193","CWE-194",
    "CWE-195","CWE-196","CWE-197","CWE-198","CWE-20",
    "CWE-200","CWE-201","CWE-202","CWE-203","CWE-204",
    "CWE-205","CWE-206","CWE-207","CWE-208","CWE-209",
    "CWE-210","CWE-211","CWE-212","CWE-213","CWE-214",
    "CWE-215","CWE-216","CWE-219","CWE-22","CWE-220",
    "CWE-221","CWE-222","CWE-223","CWE-224","CWE-226",
    "CWE-228","CWE-229","CWE-23","CWE-230","CWE-231",
    "CWE-232","CWE-233","CWE-234","CWE-235","CWE-236",
    "CWE-237","CWE-238","CWE-239","CWE-24","CWE-240",
    "CWE-241","CWE-242","CWE-243","CWE-244","CWE-245",
    "CWE-246","CWE-248","CWE-25","CWE-250","CWE-252",
    "CWE-253","CWE-256","CWE-257","CWE-258","CWE-259",
    "CWE-26","CWE-260","CWE-261","CWE-262","CWE-263",
    "CWE-266","CWE-267","CWE-268","CWE-269","CWE-27",
    "CWE-270","CWE-271","CWE-272","CWE-273","CWE-274",
    "CWE-276","CWE-277","CWE-278","CWE-279","CWE-28",
    "CWE-280","CWE-281","CWE-282","CWE-283","CWE-284",
    "CWE-285","CWE-286","CWE-287","CWE-288","CWE-289",
    "CWE-29","CWE-290","CWE-291","CWE-293","CWE-294",
    "CWE-295","CWE-296","CWE-297","CWE-298","CWE-299",
    "CWE-30","CWE-300","CWE-301","CWE-302","CWE-303",
    "CWE-304","CWE-305","CWE-306","CWE-307","CWE-308",
    "CWE-309","CWE-31","CWE-311","CWE-312","CWE-313",
    "CWE-314","CWE-315","CWE-316","CWE-317","CWE-318",
    "CWE-319","CWE-32","CWE-321","CWE-322","CWE-323",
    "CWE-324","CWE-325","CWE-326","CWE-327","CWE-328",
    "CWE-329","CWE-33","CWE-330","CWE-331","CWE-332",
    "CWE-333","CWE-334","CWE-335","CWE-336","CWE-337",
    "CWE-338","CWE-339","CWE-34","CWE-340","CWE-341",
    "CWE-342","CWE-343","CWE-344","CWE-345","CWE-346",
    "CWE-347","CWE-348","CWE-349","CWE-35","CWE-350",
    "CWE-351","CWE-352","CWE-353","CWE-354","CWE-356",
    "CWE-357","CWE-358","CWE-359","CWE-36","CWE-360",
    "CWE-362","CWE-363","CWE-364","CWE-365","CWE-366",
    "CWE-367","CWE-368","CWE-369","CWE-37","CWE-370",
    "CWE-372","CWE-374","CWE-375","CWE-377","CWE-378",
    "CWE-379","CWE-38","CWE-382","CWE-383","CWE-384",
    "CWE-385","CWE-386","CWE-39","CWE-390","CWE-391",
    "CWE-392","CWE-393","CWE-394","CWE-395","CWE-396",
    "CWE-397","CWE-40","CWE-400","CWE-401","CWE-402",
    "CWE-403","CWE-404","CWE-405","CWE-406","CWE-407",
    "CWE-408","CWE-409","CWE-41","CWE-410","CWE-412",
    "CWE-413","CWE-414","CWE-415","CWE-416","CWE-419",
    "CWE-42","CWE-420","CWE-421","CWE-422","CWE-424",
    "CWE-425","CWE-426","CWE-427","CWE-428","CWE-43",
    "CWE-430","CWE-431","CWE-432","CWE-433","CWE-434",
    "CWE-435","CWE-436","CWE-437","CWE-439","CWE-44",
    "CWE-440","CWE-441","CWE-444","CWE-446","CWE-447",
    "CWE-448","CWE-449","CWE-45","CWE-450","CWE-451",
    "CWE-453","CWE-454","CWE-455","CWE-456","CWE-457",
    "CWE-459","CWE-46","CWE-460","CWE-462","CWE-463",
    "CWE-464","CWE-466","CWE-467","CWE-468","CWE-469",
    "CWE-47","CWE-470","CWE-471","CWE-472","CWE-473",
    "CWE-474","CWE-475","CWE-476","CWE-477","CWE-478",
    "CWE-479","CWE-48","CWE-480","CWE-481","CWE-482",
    "CWE-483","CWE-484","CWE-486","CWE-487","CWE-488",
    "CWE-489","CWE-49","CWE-491","CWE-492","CWE-493",
    "CWE-494","CWE-495","CWE-496","CWE-497","CWE-498",
    "CWE-499","CWE-5","CWE-50","CWE-500","CWE-501",
    "CWE-502","CWE-506","CWE-507","CWE-508","CWE-509",
    "CWE-51","CWE-510","CWE-511","CWE-512","CWE-514",
    "CWE-515","CWE-52","CWE-520","CWE-521","CWE-522",
    "CWE-523","CWE-524","CWE-525","CWE-526","CWE-527",
    "CWE-528","CWE-529","CWE-53","CWE-530","CWE-531",
    "CWE-532","CWE-533","CWE-534","CWE-535","CWE-536",
    "CWE-537","CWE-538","CWE-539","CWE-54","CWE-540",
    "CWE-541","CWE-542","CWE-543","CWE-544","CWE-546",
    "CWE-547","CWE-548","CWE-549","CWE-55","CWE-550",
    "CWE-551","CWE-552","CWE-553","CWE-554","CWE-555",
    "CWE-556","CWE-558","CWE-56","CWE-560","CWE-561",
    "CWE-562","CWE-563","CWE-564","CWE-565","CWE-566",
    "CWE-567","CWE-568","CWE-57","CWE-570","CWE-571",
    "CWE-572","CWE-573","CWE-574","CWE-575","CWE-576",
    "CWE-577","CWE-578","CWE-579","CWE-58","CWE-580",
    "CWE-581","CWE-582","CWE-583","CWE-584","CWE-585",
    "CWE-586","CWE-587","CWE-588","CWE-589","CWE-59",
    "CWE-590","CWE-591","CWE-593","CWE-594","CWE-595",
    "CWE-596","CWE-597","CWE-598","CWE-599","CWE-6",
    "CWE-600","CWE-601","CWE-602","CWE-603","CWE-605",
    "CWE-606","CWE-607","CWE-608","CWE-609","CWE-61",
    "CWE-610","CWE-611","CWE-612","CWE-613","CWE-614",
    "CWE-615","CWE-616","CWE-617","CWE-618","CWE-619",
    "CWE-62","CWE-620","CWE-621","CWE-622","CWE-623",
    "CWE-624","CWE-625","CWE-626","CWE-627","CWE-628",
    "CWE-636","CWE-637","CWE-638","CWE-639","CWE-64",
    "CWE-640","CWE-641","CWE-642","CWE-643","CWE-644",
    "CWE-645","CWE-646","CWE-647","CWE-648","CWE-649",
    "CWE-65","CWE-650","CWE-651","CWE-652","CWE-653",
    "CWE-654","CWE-655","CWE-656","CWE-657","CWE-66",
    "CWE-662","CWE-663","CWE-664","CWE-665","CWE-666",
    "CWE-667","CWE-668","CWE-669","CWE-67","CWE-670",
    "CWE-671","CWE-672","CWE-673","CWE-674","CWE-675",
    "CWE-676","CWE-680","CWE-681","CWE-682","CWE-683",
    "CWE-684","CWE-685","CWE-686","CWE-687","CWE-688",
    "CWE-689","CWE-69","CWE-690","CWE-691","CWE-692",
    "CWE-693","CWE-694","CWE-695","CWE-696","CWE-697",
    "CWE-698","CWE-7","CWE-703","CWE-704","CWE-705",
    "CWE-706","CWE-707","CWE-708","CWE-710","CWE-72",
    "CWE-73","CWE-732","CWE-733","CWE-74","CWE-749",
    "CWE-75","CWE-754","CWE-755","CWE-756","CWE-757",
    "CWE-758","CWE-759","CWE-76","CWE-760","CWE-761",
    "CWE-762","CWE-763","CWE-764","CWE-765","CWE-766",
    "CWE-767","CWE-768","CWE-769","CWE-77","CWE-770",
    "CWE-771","CWE-772","CWE-773","CWE-774","CWE-775",
    "CWE-776","CWE-777","CWE-778","CWE-779","CWE-78",
    "CWE-780","CWE-781","CWE-782","CWE-783","CWE-784",
    "CWE-785","CWE-786","CWE-787","CWE-788","CWE-789",
    "CWE-79","CWE-790","CWE-791","CWE-792","CWE-793",
    "CWE-794","CWE-795","CWE-796","CWE-797","CWE-798",
    "CWE-799","CWE-8","CWE-80","CWE-804","CWE-805",
    "CWE-806","CWE-807","CWE-81","CWE-82","CWE-820",
    "CWE-821","CWE-822","CWE-823","CWE-824","CWE-825",
    "CWE-826","CWE-827","CWE-828","CWE-829","CWE-83",
    "CWE-830","CWE-831","CWE-832","CWE-833","CWE-834",
    "CWE-835","CWE-836","CWE-837","CWE-838","CWE-839",
    "CWE-84","CWE-841","CWE-842","CWE-843","CWE-85",
    "CWE-86","CWE-862","CWE-863","CWE-87","CWE-88",
    "CWE-89","CWE-9","CWE-90","CWE-908","CWE-909",
    "CWE-91","CWE-910","CWE-911","CWE-912","CWE-913",
    "CWE-914","CWE-915","CWE-916","CWE-917","CWE-918",
    "CWE-920","CWE-921","CWE-922","CWE-923","CWE-924",
    "CWE-925","CWE-926","CWE-927","CWE-93","CWE-939",
    "CWE-94","CWE-940","CWE-941","CWE-942","CWE-943",
    "CWE-95","CWE-96","CWE-97","CWE-98","CWE-99","CWE-NVD-noinfo"]

    def __init__(self):
        # general attributes
        self.id = id
        self.description = ""
        self.published_date = ""
        self.modified_date = ""
        # CWE 
        self.cwe = ""
        #self.projects = set()
        # Common Vulnerability Scoring System metrics
        #   baseMetricsV2
        self.cvssV2_vector_string = ""
        self.cvssV2_access_vector = ""
        self.cvssV2_access_complexity = ""
        self.cvssV2_authentication = ""
        self.cvssV2_confidentiality_impact = ""
        self.cvssV2_integrity_impact = ""
        self.cvssV2_availability_impact = ""
        self.cvssV2_base_score = 0
        #   Severity metrics
        self.severity = ""
        self.exploitation_score = -1
        self.impact_score = -1
        self.obtain_all_privilege = None
        self.obtain_user_privilege = None
        self.obtain_other_privilege = None
        self.user_interaction_required = None
        # Vulnerability references
        # self.vuln_source = ""
        # self.vuln_reference = set()
        # OVAL optional metrics
        # self.oval_definition = ""
        # self.security_protection = ""
        # self.assessment_checks = set()


    def print(self):
        print("CVE: %s" % self.id)
        print("\tDescription: %s" % self.description)
        # print versions of projects
        print("\tPublished date: %s" % self.published_date)
        print("\tModified date: %s" % self.modified_date)
        print("\tCWE: %s" % self.cwe)
        # print("\t::Affected projects::")
        # for index, project in enumerate(self.projects):
        #     print("\t%d. %s" % (index, project))
        print("\t::CVSS base_metrics::")
        print("\t\tVector string: %s" % self.cvssV2_vector_string)
        print("\t\tAccess vector: %s" % self.cvssV2_access_vector)
        print("\t\tAccess complexity: %s" % self.cvssV2_access_complexity)
        print("\t\tAuthentication: %s" % self.cvssV2_authentication)
        print("\t\tConfidentiality: %s" % self.cvssV2_confidentiality_impact)
        print("\t\tIntegrity impact: %s" % self.cvssV2_integrity_impact)
        print("\t\tAvailability impact: %s" % self.cvssV2_availability_impact)
        print("\t\tBase score: %s" % self.cvssV2_base_score)
        print("\t::Severity metrics::")
        print("\tSeverity : %s" % self.severity)
        print("\tExploitation score : %s" % self.exploitation_score)
        print("\tImpact score : %s" % self.impact_score)
        print("\tObtain all privilege : %s" % self.obtain_all_privilege)
        print("\tObtain user privilege : %s" % self.obtain_user_privilege)
        print("\tObtain other privilege : %s" % self.obtain_other_privilege)
        print("\tUser interaction required : %s" % self.user_interaction_required)


    def getDateFormatedForSQL(self, date):
        return date[:date.index('T')]


    def getBooleanFormattedForSql(self, value):
        if str(value).lower() == "true":
            return 1
        else:
            return 0
        # return str(value).lower()


    def writeCVEtoDB(self, db, cursor):
        insert = self.getSQLInsertStatement()
        # print(insert)# DEBUG
        try:
            cursor.execute(insert)
            db.commit()
        except (db.Error, db.Warning) as e:
            print(insert)
            print(e)


    def getSQLInsertStatement(self):
        # FIXME move this check to a more appropriate place
        if self.cwe not in CVE.cwes:
            self.cwe = "NVD-Other"

        insert = (
            "INSERT INTO cve ("
            # general attributes
            "id,"
            "description,"
            "published_date,"
            "modified_date,"
            # cwe
            "cwe,"
            # cvssV2 metrics
            "cvssV2_vector_string,"
            "cvssV2_access_vector,"
            "cvssV2_access_complexity,"
            "cvssV2_authentication,"
            "cvssV2_confidentiality_impact,"
            "cvssV2_integrity_impact,"
            "cvssV2_availability_impact,"
            "cvssV2_base_score,"
            "severity,"
            "exploitation_score,"
            "impact_score,"
            "obtain_all_privilege,"
            "obtain_user_privilege,"
            "obtain_other_privilege,"
            "user_interaction_required"
        ") VALUES ("
        # general attributes
        "'{}'," # id
        "'{}'," # description
        "'{}'," # published date
        "'{}'," # modified date
        # cwe
        "'CWE-{}'," # cwe
        # cvssV2 metrics
        "'{}'," # cvssV2_vector_string
        "'{}'," # cvssV2_access_vector
        "'{}'," # cvssV2_access_complexity
        "'{}'," # cvssV2_authentication
        "'{}'," # cvssV2_confidentiality_impact
        "'{}'," # cvssV2_integrity_impact
        "'{}'," # cvssV2_availability_impact
        "{}," # cvssV2_base_score
        "'{}'," # severity
        "{}," # exploitation_score
        "{}," # impact_score
        "'{}'," # obtain_all_privilege
        "'{}'," # obtain_user_privilege
        "'{}'," # obtain_other_privilege
        "'{}'" # user_interaction_required
        ")"
        ).format(
            self.id,
            self.description[:998],
            self.getDateFormatedForSQL(self.published_date),
            self.getDateFormatedForSQL(self.modified_date),
            self.cwe,
            self.cvssV2_vector_string,
            self.cvssV2_access_vector,
            self.cvssV2_access_complexity,
            self.cvssV2_authentication,
            self.cvssV2_confidentiality_impact,
            self.cvssV2_integrity_impact,
            self.cvssV2_availability_impact,
            self.cvssV2_base_score,
            self.severity,
            self.exploitation_score,
            self.impact_score,
            self.getBooleanFormattedForSql(self.obtain_all_privilege),
            self.getBooleanFormattedForSql(self.obtain_user_privilege),
            self.getBooleanFormattedForSql(self.obtain_other_privilege),
            self.getBooleanFormattedForSql(self.user_interaction_required)
        )

        return insert
