from flask import Flask, render_template, request
import json
from flask_jsonpify import jsonify
from operator import itemgetter

app = Flask(__name__)

full_data = []

current_data = full_data.copy()

json_file_info = ["nvdcve-1.0-recent.json"]#, "nvdcve-1.0-modified.json"]

def getInput(fileName):
    with open(fileName) as f:
        data = json.load(f)
    return data

def processInput(data):
    for i in data["CVE_Items"]:
        entry = {}
        entry["ID"] = i["cve"]["CVE_data_meta"]["ID"]
        if len(i["cve"]["problemtype"]["problemtype_data"]) > 0:
            if len(i["cve"]["problemtype"]["problemtype_data"][0]["description"]) > 0:
                entry["problem_type"] = i["cve"]["problemtype"]["problemtype_data"][0]["description"][0]["value"]
            else:
                entry["problem_type"] = "N/A"
        else:
            entry["problem_type"] = "N/A"
        if len(i["cve"]["description"]["description_data"]) > 0:
            entry["description"] = i["cve"]["description"]["description_data"][0]["value"]
        else:
            entry["description"] = "N/A"
        if bool(i["impact"]):
            entry["accessVector"] = i["impact"]["baseMetricV2"]["cvssV2"]["accessVector"]
            entry["severity"] = i["impact"]["baseMetricV2"]["severity"]
            entry["metricV2BaseScore"] = i["impact"]["baseMetricV2"]["cvssV2"]["baseScore"]
            if "baseMetricV3" in i["impact"]:
                entry["metricV3BaseScore"] = i["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
            else:
                entry["metricV3BaseScore"] = -1
        else:
            entry["accessVector"] = "N/A"
            entry["severity"] = "N/A"
            entry["metricV2BaseScore"] = -1
            entry["metricV3BaseScore"] = -1

        entry["publishedDate"] = i["publishedDate"]
        entry["lastModifiedDate"] = i["lastModifiedDate"]
        full_data.append(entry)

def testFunction():
    data = getInput("test.json")
    processInput(data)
    global current_data
    current_data = full_data.copy()
    return full_data

@app.route('/', methods=['GET', 'POST'])
def start():
    for json in json_file_info:
       data = getInput(json)
       processInput(data)
    global current_data
    current_data = full_data.copy()
    #print(current_data)
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
