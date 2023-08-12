#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# syncdata.py is a program which uploads and downloads data from and to pastebin.com using the pastebin API.
# accepts a command line flags:
# --action for selcting between upload and download of data. accepted values are "push" or "pull"
# --source for selecting where to upload or download data from. accepted values are "stdin", "stdout" or "file"
# stdin source is can be used when --action is "push" and stdout source can be used when --action is "pull"
# data is always uploaded to pastebin.com and downloaded from pastebin.com, the only difference is the source and destination of the data

import argparse
import loguru as logger
from urllib import request, parse, error as urllib_error
import sys

PASTEBIN_POST_TARGET = "https://pastebin.com/api/api_post.php"
PASTEBIN_GET_DATA_TARGET_FORMAT = "https://pastebin.com/raw/%s"

#refactor this function to use argparse properly
#usage examples:
    # python3 syncdata.py --action push --source stdin --developer_api_key 1234567890abcdef
    # python3 syncdata.py --action push --source file --file /home/user/file.txt --developer_api_key 1234567890abcdef
    # python3 syncdata.py --action pull --source stdout --object f1nb6pXQ --developer_api_key 1234567890abcdef
    # python3 syncdata.py --action pull --source file --file /home/user/file.txt --object f1nb6pXQ --developer_api_key 1234567890abcdef
def parse_arguments():
    # if action pull is specified then token must be specified too.
    parser = argparse.ArgumentParser(description="Uploads and downloads data from and to pastebin.com using the pastebin API" + "",)
    parser.add_argument("--action", help="< push | pull >selects between upload and download of data", required=True, options=["push", "pull"])
    parser.add_argument("--source", help="selects where to upload or download data from", required=True)
    parser.add_argument("--file", help="< file| stdin | stdout > selects the file to upload or download", required=False, ops=["file", "stdin", "stdout"])
    #parse developer key:
    parser.add_argument("--developer_api_key", help="pastebin developer key", required=True)
    #example value: "f1nb6pXQ"
    parser.add_argument("--object", help="pastebin file specifier", nargs="?")
    args = parser.parse_args()
    if args.action != "push" and args.action != "pull":
        logger.logger.error("Invalid action")
        exit(1)
    if args.action == "pull" and args.object is None:
        logger.logger.error("object is not specified")
        exit(1)

    if args.source == "file" and args.file is None:
        logger.logger.error("file is not specified")
        exit(1)
    return args

# the fucntion accepts a pastebin file specifier such as "f1nb6pXQ" and returns the URL of the file such as "https://pastebin.com/f1nb6pXQ"
def pastebin_file_specifier_to_url(file_specifier):
    return "https://pastebin.com/" + file_specifier    

def upload_data(data_to_upload:str, developer_key:str) -> str:
    request_dict = {
            'api_dev_key': developer_key,
            'api_paste_code': data_to_upload,
            'api_option': 'paste'}
    logger.logger.info("request dict is %s" % request_dict)
    encoded_request_data = parse.urlencode(request_dict).encode()
    req =  request.Request(PASTEBIN_POST_TARGET, data=encoded_request_data, method='POST') 
    logger.logger.info("request created")
    try: 
        resp = request.urlopen(req)
    except urllib_error.HTTPError as e:
        logger.logger.error("Failed to upload data to pastebin.com, error: %s" % str(e.read()))
        exit(1)
    if resp.status != 200:
        raise Exception("Failed to upload data to pastebin.com, error code: %s, error data: %s" % (resp.status, resp.read()))
    
    return resp.read().decode()


def get_data_from_pastebin(file_specifier:str) -> str:
    url = PASTEBIN_GET_DATA_TARGET_FORMAT % file_specifier
    req =  request.Request(url, method='GET') 
    resp = request.urlopen(req)
    if resp.status != 200:
        raise Exception("Failed to download data from pastebin.com, error code: %s, error data: %s" % (resp.status, resp.read()))
    
    return resp.read().decode()

def exteact_url_last_part_from_pastebin_url(url):
    return url.split("/")[-1]

def init_logger():    
    logger.logger.remove()
    logger.logger.add(sys.stdout, colorize=True, format="<green>{time:YYYY-MM-DD at HH:mm:ss}</green> <lvl>{message}</lvl>", level="INFO")

    
@logger.logger.catch
def main():
    init_logger()
    logger.logger.info("syncdata started")

    args = parse_arguments()
    developer_key = args.developer_api_key
    #upload or download data
    if args.action == "push":
        if args.source == "stdin":
            data = input("Enter data to upload: ")
        elif args.source == "file":
            data = open(args.file, "r").read()
        else:
            logger.logger.error( "Invalid source")
            exit(1)
        logger.logger.info( "read data successfully")
        url = upload_data(data, developer_key)
        logger.logger.info( "Paste created at: " + url)
        logger.logger.info( ">>> (%s)" % exteact_url_last_part_from_pastebin_url(url))

    elif args.action == "pull":
        if args.source != "stdout" and args.source != "file":
            logger.logger.error( "Invalid source")
            exit(1)
        data = get_data_from_pastebin(args.object)
        if args.source == "stdout":
            logger.logger.info( "Data downloaded: " + data)
        elif args.source == "file":
            with open(args.file, "w") as f:
                f.write(data)
            
    else:
        logger.logger.error("Invalid action")
        exit(1)
    

if __name__ == "__main__":
    main()
