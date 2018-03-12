import re

from project import Project, ProjectList
from utility import Utility

class RepoHistoryAnalyzer(object):

    regex_rules = {
        "xen:xen":[
                [r'(RELEASE-)',''], # remove RELEASE-
                [r'(.0)$',r''] # remove a dot.zero from the end to match 2.0 to 2.0.0 
        ],
        "apache:http_server":[
                ['',''] # do nothing
        ],
        "apache:struts":[
                [r'(STRUTS_)',''], # remove STRUTS_
                [r'_',r'.']
        ],
        "apache:subversion":[
                ['',''] # do nothing
        ],
        "apache:tomcat":[
                [r'(TOMCAT_)',''], # remove TOMCAT_
                [r'_',r'.'],        # replace _ with .
                [r'(.*)(.0)',r'\1'] # remove a dot.zero from the end to match 2.0 to 2.0.0 
        ],
        "apple:cups":[
                [r'(release-)',''], # remove release-
                [r'(.*)(.0)',r'\1'] # remove a dot.zero from the end to match 2.0 to 2.0.0 
        ],
        "apple:darwin_streaming_server":[
                ['',''], # do nothing
                [r'^v',''],
                [r'(.0)$',r'']
        ],
        "autotrace_project:autotrace":[
                ['',''] # do nothing
        ],
        "bestpractical:rt":[
                [r'(rt-)',''], # remove rt-
                [r'(.*)(.0)',r'\1'] # remove a dot.zero from the end to match 2.0 to 2.0.0 
        ],
        "bigtreecms:bigtree_cms":[
                ['','']
        ],
        "cacti:cacti":[
                [r'^(release-|v)',''] # remove release- and v from the beginning
        ],
        "clamav:clamav":[
                [r'^(clamav-)',''], # remove clamav- and v from the beginning
                [r'^(CLAMAV_)',''], # remove clamav- and v from the beginning
                [r'(.*)(rc|RC)',r'\1 \2'],
                [r'_',r'.'],
                [r'(rc.*)',r'_\1'],
                [r'\s+',r'_']
        ],
        "cmsmadesimple:cms_made_simple":[
                [r'.*(version-)(.*)',r'\2'], # remove version-
                [r'v',r''], # v from the beginning
                [r'/$',r''] # remove / from the end
        ],
        # "coppermine:coppermine_photo_gallery":[
        #         [r'^v',''] # remove v from the biginning
        # ], # no matching tags
        "devellion:cubecart":[
                [r'^v',''] # remove v from the biginning
        ],
        "digium:asterisk":[
                ['',''], # do nothing
                [r'-',r' ']
        ],
        "djangoproject:django":[
                ['',''] # do nothing
        ],
        "dotclear:dotclear":[
                ['',''] # do nothing
        ],
        "dotcms:dotcms":[
                ['',''] # do nothing
        ],
        "dotnetnuke:dotnetnuke":[
                [r'^v',''],
                [r'-alpha$',r'']
        ],
        "dovecot:dovecot":[
                ['',''] # do nothing
        ],
        "drupal:drupal":[
                ['',''] # do nothing
        ],
        "e107:e107":[
                [r'^v','']
        ],
        "exponentcms:exponent_cms":[
                [r'^v','']
        ],
        "fetchmail:fetchmail":[
                [r'(RELEASE_)',''],
                [r'-',r'.']
        ],
        "firebirdsql:firebird":[
                [r'[R]',''],
                [r'_',r'.']
        ],
        "freebsd:freebsd":[
                [r'remotes\/origin\/release\/',''],
                [r'(.*)(.0)',r'\1']
        ],
        "freeradius:freeradius":[
                [r'(release_)',''],
                [r'_',r'.']
        ],
        "freetype:freetype":[
                [r'(VER-)',''],
                [r'-',r'.'],
                [r'(.0)$','']
        ],
        "gnu:glibc":[
                [r'(glibc-)',''],
                [r'-',r'.'],
                [r'(.*)(.0)',r'\1']
        ],
        "gnu:gnutls":[
                [r'(gnutls_)',''],
                [r'_',r'.'],
                [r'(.0)$',r'']
        ],
        "google:v8":[
                ['',''] # do nothing
        ],
        "libcurl:libcurl":[
                [r'(curl-)',''],
                [r'_',r'.']
        ],
        "horde:groupware":[
                [r'^v','']
        ],
        "irssi:irssi":[
                ['',''] # do nothing
        ],
        "isc:bind":[
                [r'^v',''],
                [r'(_ESV_R)',r'-esv-r'],
                [r'(_P)',r'-p'],
                [r'(_W)',r'-w'],
                [r'_',r'.']
        ],
        "jenkins:jenkins":[
                [r'^(jenkin-)',''],
                [r'^(jenkins-)',''],
                [r'0$','']
        ],
        "joomla:joomla":[
                ['',''],
                [r'-',' ']
        ],
        "kde:konqueror":[
                [r'^v','']
        ],
        "libarchive:libarchive":[
                [r'^v','']
        ],
        "libav:libav":[
                [r'^v','']
        ],
        "libgd:libgd":[
                [r'^(GD_|gd-)',''],
                [r'_',r'.']
        ],
        "libpng:libpng":[
                [r'^v',''],
                [r'^(libpng-)',''],
                [r'(-signed)','']
        ],
        "libreoffice:libreoffice":[
                [r'^v',''],
                [r'^(libreoffice-)',''],
                [r'^(cp-)',''],
                [r'(-branch-point)',''],
                [r'(.*)',r'\1.0']
        ],
        "libtiff:libtiff":[
                [r'^(Release-v)',''],
                [r'_',r'.'],
                [r'(.0)$',r'']
        ],
        "lighttpd:lighttpd":[
                [r'^(lighttpd-)','']
        ],
        "linux:linux_kernel":[
                [r'^v','']
        ],
        "lockon:ec-cube":[
                ['',''],
                [r'^(eccube-)','']
        ],
        "mahara:mahara":[
                [r'(_RELEASE)','']
        ],
        "mantis:mantis":[
                [r'^(release-)','']
        ],
        "mariadb:mariadb":[
                [r'^(mariadb-)','']
        ],
        "mediawiki:mediawiki":[
                ['',''],
                [r'(beta|alpha)',r' \1'],
                [r'.0 ','_']
        ],
        "mit:kerberos":[
                [r'^(kfw-|krb)',''],
                [r'(-final)','']
        ],
        "modx:modx_revolution":[
                [r'^v',''],
                [r'(-pl)','']
        ],
        "moodle:moodle":[
                [r'^v',''],
                [r'-',' ']
        ],
        "mozilla:bugzilla":[
                [r'^(release-)',''],
                [r'(rc)',r' rc']
        ],
        "mybb:mybb":[
                [r'^(mybb_)',''],
                [r'(\d){1}(\d){1}(0){1}',r'\1.\2'],
                [r'(\d){1}(\d){1}(\d){1}(\d)*',r'\1.\2.\3\4']
        ],
        "nagios:nagios":[
                [r'^(nagios-)','']
        ],
        "nodejs:node.js":[
                [r'^v','']
        ],
        "ntp:ntp":[
                [r'(openafs-stable-)',''],
                [r'-',''],
                [r'_',r'.'],
                [r'(rc|pre|fc|beta)',r'_\1']

        ],
        "openjpeg:openjpeg":[
                [r'^(version.|v)',''],
                [r'(.*)',r'\1.0']
        ],
        "openldap:openldap":[
                [r'^(OPENLDAP_REL_ENG_)',''],
                [r'_',r'.'],
                [r'(.0)$',r'']
        ],
        "openssl:openssl":[
                [r'^(OpenSSL_)',''],
                [r'_',r'.']
        ],
        "openstack:keystone":[
                ['',''] # do nothing
        ],
        "oracle:glassfish_server":[
                ['',''] # do nothing
        ],
        "oracle:glassfish_server":[
                [r'^v','']
        ],
        "otrs:otrs":[
                [r'^(rel-)',''],
                [r'_',r'.']
        ],
        "owncloud:owncloud":[
                [r'^v','']
        ],
        "perl:perl":[
                [r'^(v|perl-)',''],
                [r'.0$',r'.00']
        ],
        "phorum:phorum":[
                [r'^(phorum_)',''],
                [r'_',r'.'],
                [r'(.)(beta|alpha)',r' \1'],
                [r'(.rc|.RC)',r'.rc']
        ],
        "phpbb_group:phpbb":[
                [r'^(release-)','']
        ],
        "phpgroupware:phpgroupware":[
                [r'^(.*Version-)',''],
                ['/',''],
                [r'_',r'.']
        ], # svn. matches are not correct. do it manually
        "phpmyadmin:phpmyadmin":[
                [r'^(RELEASE_)',''],
                [r'_',r'.'],
                [r'(RC)',r'_rc'],
                [r'(ALPHA)',r'_alpha'],
                [r'(BETA)',r'_beta']
        ],
        "phpmyfaq:phpmyfaq":[
                ['',''],
                [r'-',r'_']
        ],
        "piwigo:piwigo":[
                ['',''],
                [r'(.*)',r'\1.0']
        ],
        "pligg:pligg_cms":[
                ['','']
        ],
        "plone:plone":[
                ['',''],
                [r'-',r'_']
        ],
        "poppler:poppler":[
                [r'^(poppler-)','']
        ],
        "postgresql:postgresql":[
                [r'^(REL)',''],
                [r'_',r'.'],
                [r'(.0)$',r'']
        ],
        "puppetlabs:puppet":[
                ['','']
        ],
        "python:python":[
                [r'^v',''],
                [r'(.0)$',r'']
        ],
        "quagga:quagga":[
                [r'^(RE-|quagga-|quagga_)',''],
                [r'_',r'.'],
                [r'(.0)$',r'']
        ],
        "redhat:openshift":[
                [r'^v',''],
                [r'(.0)$',r'']
        ],
        "revive-adserver:revive_adserver":[
                [r'^v','']
        ],
        "roundcube:webmail":[
                ['',''],
                [r'^v',''],
                [r'(-stable)','']
        ],
        "ruby-lang:ruby":[
                [r'^v',''],
                [r'_([.*^_]*)$',r'-\1'],
                [r'_',r'.'],
                [r'(.0)$',r''],
                [r'(.0)$',r''],
                [r'(.*)',r'\1.0.0']
        ],
        "rubyonrails:ruby_on_rails":[
                [r'^v','']
        ],
        "s9y:serendipity":[
                ['',''],
                [r'(.0)$',r'']
        ],
        "samba:samba":[
                [r'^(samba-)',''],
                [r'(.0)$',r'']
        ],
        "silverstripe:silverstripe":[
                ['','']
        ],
        "spip:spip":[
                [r'^(spip-)',''],
                [r'(.0)$',r'']
        ],
        "squid:squid":[
                [r'^(SQUID_)',''],
                [r'_',r'.'],
                [r'(STABLE)',r'stable'],
                [r'(PRE)',r'pre'],
                [r'(RC)',r'rc']
        ],
        "ssh:ssh":[
                [r'^(libssh-|release-)',''],
                [r'(.0)$',r''],
                [r'-',r'.']
        ],
        "php:php":[
                [r'^(php-)',''],
                [r'(.0)$',r'']
        ],
        "ffmpeg:ffmpeg":[
                [r'^n','']
        ],
        "qemu:qemu":[
                [r'^v','']
        ],
        "todd_miller:sudo":[
                [r'^(SUDO_)',''],
                [r'( )+.*$',''],
                [r'_',r'.'],
                [r'p',r'_p']
        ], 
        "pidgin:pidgin":[
                [r'^(v)',''],
                [r'( )+.*$','']
        ],
        "xine:xine-lib":[
                [r'( )+.*$','']
        ],
        "xorg:x11":[
                [r'( )+.*$','']
        ],
        "wireshark:wireshark":[
                [r'^(wireshark-)','']
        ],
        "webmin:webmin":[
                ['','']
        ],
        "w3m_project:w3m":[
                [r'^(debian/|upstream/|v)','']
        ],
        "videolan:vlc_media_player":[
                [r'(-git)','']
        ],
        "typo3:typo3":[
                [r'^(TYPO3_)',''],
                [r'-',r'.'],
                [r'(.0)$',r'']
        ],
        "tor:tor":[
                [r'^(tor-)',''],
                [r'-',r'_'],
                [r'(.0)$',r'']
        ],
        "tiki:tikiwiki":[
                ['',''],
                [r'(.*)',r'\1.0']
        ],
        "theforeman:foreman":[
                ['','']
        ],
        "tcpdump:tcpdump":[
                [r'^(tcpdump-)','']
        ],
        "graphicsmagick:graphicsmagick":[
                [r'^(ImageMagick-|GraphicsMagick-)',''],
                [r'( )+.*$',''],
                [r'_',r'.']
        ]
    }


    def __init__(self):
        # print("Created RepoHistoryAnalyzer..")
        pass


    def analyze(self, project):
        project_vendor_name = "{}:{}".format(project.vendor,project.name)
        project.vulnerable_versions = dict.fromkeys(project.versions_with_cves.keys(),"")
        if project_vendor_name not in RepoHistoryAnalyzer.regex_rules:
            print("No rules for {}. Skipping commit analysis.".format(project_vendor_name))
            return
          # print("@RepoHistoryAnalyzer ==> Analyzing {}:{}\n\t{}\n\t{}".format(
          # project.vendor,project.name,project.repo_url,project.local_repo_dir))
        print("@RepoHistoryAnalyzer ==> Analyzing {}".format(project_vendor_name))
        tag_lines = self.retrieve_commit_references(project)
        self.make_matching(project_vendor_name, project.repo_type, project.vulnerable_versions, tag_lines)
        # print(project.vulnerable_versions)
        # for version in project.vulnerable_versions:
        #     print("{}:{}".format(version,project.vulnerable_versions[version]))


    def clean_mercurial_version_string(self,string):
        rule = [r'( )+.*$','']
        cleaned_tag = re.sub(rule[0], rule[1], string).strip()
        return cleaned_tag


    def clean_subversion_version_string(self,string):
        rule = [r'.*[0-9]{4} (.*)$',r'\1']
        cleaned_tag = re.sub(rule[0], rule[1], string).strip()
        return cleaned_tag


    def make_matching(self, project_vendor_name, repo_type, versions, tag_lines):
        for tag in tag_lines:
            original_tag = tag
            # print(tag)
            project_rules = RepoHistoryAnalyzer.regex_rules[project_vendor_name]
            for rule in project_rules:
                # print("rule: {}".format(rule))
                tag = re.sub(rule[0], rule[1], tag).strip()
                # print("{}".format(clean_tag))
                if tag in versions:
                    if repo_type == "hg":
                        cleaned_tag = self.clean_mercurial_version_string(original_tag)
                        # print("Original HG:{}\nCleaned:{}".format(original_tag, cleaned_tag))
                        versions[tag] = cleaned_tag
                    elif repo_type == "svn":
                        cleaned_tag = self.clean_subversion_version_string(original_tag)
                        # print("Original SVN:{}\nCleaned:{}".format(original_tag, cleaned_tag))
                        versions[tag] = cleaned_tag
                    else:
                        versions[tag] = original_tag.strip()
        

    def retrieve_commit_references(self, project):
        cvs_command = ""
        if project.repo_type == "git":
            cvs_command = self.analyze_git(project)
        elif project.repo_type == "hg":
            cvs_command = self.analyze_mercurial(project)
        elif project.repo_type == "svn":
            cvs_command = self.analyze_subversion(project)
        else:
            print("UNKKOWN commit reference {}:{}={}".format(project.name,project.vendor,project.repo_type))
            return

        cvs_command_output = Utility.execute_process(cvs_command).splitlines()
        # print("\t\tOutput {}.".format(cvs_command_output[:]))
        # commit_references = repo_output.split()
        return cvs_command_output
    

    def analyze_git(self, project):
        # print("\tcreating git cvs command")
        if project.commit_reference == "tag":
            git_command = "git -C {} tag".format(project.local_repo_dir)
        elif project.commit_reference == "branch":
            git_command = "git -C {} branch -a".format(project.local_repo_dir)
        else:
            print("## ERROR ## unknown cvs reference type")
            return ""

        return git_command


    def analyze_mercurial(self, project):
        # print("\tcreating mercurial cvs command")
        hg_command = "hg tags -R {}".format(project.local_repo_dir)
        # print(hg_command)
        return hg_command

    def analyze_subversion(self, project):
        # print("\tcreating subversion cvs command")
        svn_command = "svn ls -v ^/tags {}".format(project.local_repo_dir)
        # print(svn_command)
        return svn_command

