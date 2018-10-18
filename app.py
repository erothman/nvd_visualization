from flask import Flask, render_template, request
import json
from flask_jsonpify import jsonify
from operator import itemgetter

app = Flask(__name__)

full_data = []

current_data = []

ID_list = []

json_file_info = ["nvdcve-1.0-recent.json"]#, "nvdcve-1.0-modified.json"]

#This function is only for the purposes of unit testing. It resets the full_data and current_data back to null to test getting input.
def reset_test():
    global full_data
    global current_data
    global ID_list
    full_data = []
    current_data= full_data.copy()
    ID_list = []

#This function gets input from a json file.
def get_input(fileName):
    with open(fileName) as f:
        data = json.load(f)
    return data

#This function process a json input into a shorter list that contains information from NVD formatted data.
def process_input(data):
    global ID_list
    for i in data["CVE_Items"]:
        entry = {}
        entry["ID"] = i["cve"]["CVE_data_meta"]["ID"]
        entry["vendors_affected"] = []
        entry["products_affected"] = []
        for vendor in i["cve"]["affects"]["vendor"]["vendor_data"]:
            entry["vendors_affected"].append(vendor["vendor_name"])
            for product in vendor["product"]["product_data"]:
                entry["products_affected"].append(product["product_name"])
        if len(i["cve"]["problemtype"]["problemtype_data"]) > 0:
            if len(i["cve"]["problemtype"]["problemtype_data"][0]["description"]) > 0:
                entry["problem_type"] = i["cve"]["problemtype"]["problemtype_data"][0]["description"][0]["value"]
            else:
                entry["problem_type"] = "N/A"
        else:
            entry["problem_type"] = "N/A"
        entry["references"] = i["cve"]["references"]["reference_data"]
        if len(i["cve"]["description"]["description_data"]) > 0:
            entry["description"] = i["cve"]["description"]["description_data"][0]["value"]
        else:
            entry["description"] = "N/A"
        if bool(i["impact"]):
            entry["accessVector"] = i["impact"]["baseMetricV2"]["cvssV2"]["accessVector"]
            entry["severity"] = i["impact"]["baseMetricV2"]["severity"]
            entry["metricV2BaseScore"] = i["impact"]["baseMetricV2"]["cvssV2"]["baseScore"]
            entry["metricV2ExploitabilityScore"] = i["impact"]["baseMetricV2"]["exploitabilityScore"]
            entry["metricV2ImpactScore"] = i["impact"]["baseMetricV2"]["impactScore"]
            if "baseMetricV3" in i["impact"]:
                entry["metricV3BaseScore"] = i["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
                entry["metricV3ExploitabilityScore"] = i["impact"]["baseMetricV3"]["exploitabilityScore"]
                entry["metricV3ImpactScore"] = i["impact"]["baseMetricV3"]["impactScore"]

            else:
                entry["metricV3BaseScore"] = -1.0
                entry["metricV3ExploitabilityScore"] = -1.0
                entry["metricV3ImpactScore"] = -1.0
        else:
            entry["accessVector"] = "N/A"
            entry["severity"] = "N/A"
            entry["metricV2BaseScore"] = -1.0
            entry["metricV3BaseScore"] = -1.0
            entry["metricV2ExploitabilityScore"] = -1.0
            entry["metricV2ImpactScore"] = -1.0
            entry["metricV3ExploitabilityScore"] = -1.0
            entry["metricV3ImpactScore"] = -1.0

        entry["publishedDate"] = i["publishedDate"] if "publishedDate" in i else "N/A"
        entry["lastModifiedDate"] = i["lastModifiedDate"] if "lastModifiedDate" in i else "N/A"

        

        if entry["ID"] not in ID_list:
            full_data.append(entry)
            ID_list.append(entry["ID"])
        else:
            for entry_search in full_data:
                if entry_search["ID"] == entry["ID"]:
                    if entry_search["lastModifiedDate"] == "N/A" or (entry["lastModifiedDate"] > entry_search["lastModifiedDate"] and entry["lastModifiedDate"] != "N/A"):
                        full_data.remove(entry_search)
                        full_data.append(entry)
                        break
    return full_data

#This function is only for testing. It tests the integration of the get input function and the process input function while also setting up current_data to test the get functions.
def test_function():
    data = get_input("testingJsons/test.json")
    process_input(data)
    global current_data
    current_data = full_data.copy()
    return full_data

@app.route('/', methods=['GET', 'POST'])
def start():
    for json in json_file_info:
       data = get_input(json)
       process_input(data)
    global current_data
    current_data = full_data.copy()
    return render_template('table.html')

@app.route('/getData', methods=['GET'])
def get_data():
    return jsonify(current_data)

@app.route('/getDataOrdered/<field>/<reverse>', methods=['GET'])
def get_data_ordered(field, reverse=None):
    global current_data
    if reverse == 'true':
        data = sorted(current_data, key=itemgetter(field), reverse=True)
    else:
        data = sorted(current_data, key=itemgetter(field), reverse=False)
    current_data = data
    return jsonify(current_data)

@app.route('/getDataQuery/', methods=['GET'])
def reset_data():
    global current_data
    current_data = full_data
    return jsonify(current_data)

@app.route('/getDataQuery/<queryTerm>', methods=['GET'])
def get_data_query(queryTerm):
    global current_data
    current_data = []
    query = str(queryTerm)
    for data in full_data:
        flag = False
        for key, value in data.items():
            if query in str(value):
                flag = True
        if flag:
            current_data.append(data)
    return jsonify(current_data)

if __name__ == '__main__':
     app.run(port=5002)
