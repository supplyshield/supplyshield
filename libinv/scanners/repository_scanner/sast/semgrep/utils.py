import datetime
import hashlib
import os
import re
import subprocess
import uuid
from random import randint
from urllib.parse import urlparse


def getdirfromfilename(f):
    return os.path.dirname(os.path.realpath(f))


pwd = getdirfromfilename(__file__)


def getfilenamewithoutext(filepath):
    return os.path.splitext(filepath.split("/")[-1])[0]


def getdatetime():
    # Fix: `datetime` here is the module (see `import datetime` above), so
    # `datetime.today()` raised AttributeError. Use `datetime.datetime.now()`.
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def fingerprint_semgrep_single_result_sarif(semgrep, subpath):
    """
    make a unique id for semgrep result. if same semgrep result is seens twice
    it should give same unique id for both.
    """
    string = ""
    string += subpath
    string += "__::__" + str(
        semgrep["locations"][0]["physicalLocation"]["region"]["snippet"]["text"]
    )
    string += "__::__" + str(semgrep["message"])
    string += "__::__" + str(semgrep["ruleId"])
    return sha256_string(string)


def sha256_string(string):
    m = hashlib.sha256()
    m.update(bytes(string, "utf-8"))
    return m.hexdigest()


def is_valid_github_url(u):
    return u.split(":")[0] == "git@github.com"


def parseurl(u):
    return urlparse(u)


def getabsolutepath(p):
    return os.path.abspath(p)


def random_with_N_digits(n):
    range_start = 10 ** (n - 1)
    range_end = (10**n) - 1
    return randint(range_start, range_end)


def check_folder_exist(path: str) -> bool:
    if not path:
        return False
    return os.path.isdir(path)


def file_exist(path: str) -> bool:
    if not path:
        return False
    return os.path.isfile(path)


def is_folder_empty(path: str) -> bool:
    if os.listdir(path) == []:
        return True
    else:
        return False


def is_file_name_valid(fileName: str) -> bool:
    if re.search(r"^[a-zA-Z0-9_]*$", fileName):
        return True
    else:
        return False


def secure_file_name(fileName: str) -> str:
    return re.sub(r"\W+", "_", fileName)


def create_folder(folder):
    if check_folder_exist(folder):
        raise Exception("Folder " + folder + " Already Exist :: utils.create_folder")

    os.mkdir(folder)
    return True


def replace_with_uuid(path):
    def uuid_replacer(match):
        return str(uuid.uuid4())

    return re.sub(r"\{[^\}]+\}", uuid_replacer, path)
