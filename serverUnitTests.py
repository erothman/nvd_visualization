import unittest
import json
from app import *


class TestServerInputAndProcessing(unittest.TestCase):

    def test_first(self):
        self.assertEqual('foo'.upper(), 'FOO')

    def test_get_input(self):
        data = get_input("testingJsons/readTest.json")
        test_dir = {'test_item_1': [{'test_inner': 'test'},{'test_inner_2': '0'}], 'test_item_2': '1'}
        self.assertEqual(data["test_item_1"][0]["test_inner"], test_dir["test_item_1"][0]["test_inner"])
        self.assertEqual(data["test_item_1"][1]["test_inner_2"], test_dir["test_item_1"][1]["test_inner_2"])
        self.assertEqual(data["test_item_2"], test_dir["test_item_2"])

    def test_process_input_allinput(self):
        test_data = {"CVE_Items": []}
        problem_type = {"problemtype_data": [{"description": [{"value": "BAD"}]}, {"test": "fail"}]}
        description = {"description_data": [{"value": "Described"}]}
        cve = {"CVE_data_meta": {"ID": "CV-10", "other": "fail"}, "problemtype": problem_type, "description": description}
        impact = {"baseMetricV2": {"cvssV2": {"accessVector": "attack", "baseScore": 10}, "severity": "HIGH"}, "baseMetricV3": {"cvssV3": {"baseScore": 9}}}
        test_data["CVE_Items"].append({"cve": cve, "impact": impact, "extra": {"test": "fail"}, "publishedDate": "may", "lastModifiedDate": "today"})
        processed = process_input(test_data)
        good_output = [{"ID": "CV-10", "problem_type": "BAD", "description": "Described", "accessVector": "attack", "severity": "HIGH", "metricV2BaseScore": 10, "metricV3BaseScore": 9, "publishedDate": "may", "lastModifiedDate": "today"}]
        self.assertEqual(len(processed[0]), len(good_output[0]))
        self.assertEqual(len(processed), 1)
        for key, value in good_output[0].items():
            self.assertTrue(bool(processed[0][key]))
            self.assertEqual(processed[0][key], value)
        reset_test()

    def test_process_input_lacking(self):
        test2_data = {"CVE_Items": []}
        problem_type = {"problemtype_data": []}
        description = {"description_data": []}
        cve = {"CVE_data_meta": {"ID": "CV-10"}, "problemtype": problem_type, "description": description}
        impact = {}
        test2_data["CVE_Items"].append({"cve": cve, "impact": impact, "extra": {"test": "fail"}})
        problem_type = {"problemtype_data": [{"description": []}]}
        description = {"description_data": [{"value": "Described"}]}
        cve = {"CVE_data_meta": {"ID": "CV-11", "other": "fail"}, "problemtype": problem_type, "description": description}
        impact = {"baseMetricV2": {"cvssV2": {"accessVector": "attack", "baseScore": 10}, "severity": "HIGH"}}
        test2_data["CVE_Items"].append({"cve": cve, "impact": impact, "extra": {"test": "fail"}, "lastModifiedDate": "today"})
        processed = process_input(test2_data)
        good_output = [{"ID": "CV-10", "problem_type": "N/A", "description": "N/A", "accessVector": "N/A", "severity": "N/A", "metricV2BaseScore": -1, "metricV3BaseScore": -1, "publishedDate": "N/A", "lastModifiedDate": "N/A"}, {"ID": "CV-11", "problem_type": "N/A", "description": "Described", "accessVector": "attack", "severity": "HIGH", "metricV2BaseScore": 10, "metricV3BaseScore": -1, "publishedDate": "N/A", "lastModifiedDate": "today"}]
        self.assertEqual(len(processed[0]), len(good_output[0]))
        self.assertEqual(len(processed[1]), len(good_output[1]))
        self.assertEqual(len(processed), 2)
        for key, value in good_output[0].items():
            self.assertTrue(bool(processed[0][key]))
            self.assertEqual(processed[0][key], value)
        for key2, value2 in good_output[1].items():
            self.assertTrue(bool(processed[1][key2]))
            self.assertEqual(processed[1][key2], value2)
        reset_test()

    def test_combined_input_and_processing(self):
        processed_input = test_function()
        good_input1 = {"ID": "CVE-2003-1605", "problem_type": "CWE-255", "description": "curl 7.x before 7.10.7 sends CONNECT proxy credentials to the remote server.", "accessVector": "NETWORK", "severity": "MEDIUM", "metricV2BaseScore": 5.0, "metricV3BaseScore": 7.5, "publishedDate": "2018-08-23T19:29Z", "lastModifiedDate": "2018-10-15T18:20Z"}
        good_input2 = {"ID": "CVE-2011-2765", "problem_type": "CWE-59", "description": "pyro before 3.15 unsafely handles pid files in temporary directory locations and opening the pid file as root. An attacker can use this flaw to overwrite arbitrary files via symlinks.", "accessVector": "NETWORKS", "severity": "HIGH", "metricV2BaseScore": 4.0, "metricV3BaseScore": 8.0, "publishedDate": "2018-08-20T13:29Z", "lastModifiedDate": "2018-10-16T13:44Z"}
        good_input = []
        good_input.append(good_input1)
        good_input.append(good_input2)
        for key, value in good_input[0].items():
            self.assertTrue(bool(processed_input[0][key]))
            self.assertEqual(processed_input[0][key], value)
        for key2, value2 in good_input[1].items():
            self.assertTrue(bool(processed_input[1][key2]))
            self.assertEqual(processed_input[1][key2], value2)
        reset_test()


class TestServerGet(unittest.TestCase):

    def setUp(self):
        self.app = app.test_client()
        reset_test()
        good_input1 = {"ID": "CVE-2003-1605", "problem_type": "CWE-255", "description": "curl 7.x before 7.10.7 sends CONNECT proxy credentials to the remote server.", "accessVector": "NETWORK", "severity": "MEDIUM", "metricV2BaseScore": 5.0, "metricV3BaseScore": 7.5, "publishedDate": "2018-08-23T19:29Z", "lastModifiedDate": "2018-10-15T18:20Z"}
        good_input2 = {"ID": "CVE-2011-2765", "problem_type": "CWE-59", "description": "pyro before 3.15 unsafely handles pid files in temporary directory locations and opening the pid file as root. An attacker can use this flaw to overwrite arbitrary files via symlinks.", "accessVector": "NETWORKS", "severity": "HIGH", "metricV2BaseScore": 4.0, "metricV3BaseScore": 8.0, "publishedDate": "2018-08-20T13:29Z", "lastModifiedDate": "2018-10-16T13:44Z"}
        self.good_output = []
        self.good_output.append(good_input1)
        self.good_output.append(good_input2)
        test_function()

    def test_get(self):
        get_output = self.app.get('/getData').json
        for key, value in self.good_output[0].items():
            self.assertTrue(bool(get_output[0][key]))
            self.assertEqual(get_output[0][key], value)
        for key2, value2 in self.good_output[1].items():
            self.assertTrue(bool(get_output[1][key2]))
            self.assertEqual(get_output[1][key2], value2)

    def test_get_ordered_ID(self):
#        print(self.good_output)
        get_output = self.app.get('/getDataOrdered/ID/false').json
        for key, value in self.good_output[0].items():
            self.assertTrue(bool(get_output[0][key]))
            self.assertEqual(get_output[0][key], value)
        for key2, value2 in self.good_output[1].items():
            self.assertTrue(bool(get_output[1][key2]))
            self.assertEqual(get_output[1][key2], value2)

    def test_get_reverse_ID(self):
        get_output = self.app.get('/getDataOrdered/ID/true').json
        for key, value in self.good_output[1].items():
            self.assertTrue(bool(get_output[0][key]))
            self.assertEqual(get_output[0][key], value)
        for key2, value2 in self.good_output[0].items():
            self.assertTrue(bool(get_output[1][key2]))
            self.assertEqual(get_output[1][key2], value2)

    def test_get_ordered_problem_type(self):
        get_output = self.app.get('/getDataOrdered/problem_type/false').json
        for key, value in self.good_output[0].items():
            self.assertTrue(bool(get_output[0][key]))
            self.assertEqual(get_output[0][key], value)
        for key2, value2 in self.good_output[1].items():
            self.assertTrue(bool(get_output[1][key2]))
            self.assertEqual(get_output[1][key2], value2)

    def test_get_reverse_problem_type(self):
        get_output = self.app.get('/getDataOrdered/problem_type/true').json
        for key, value in self.good_output[1].items():
            self.assertTrue(bool(get_output[0][key]))
            self.assertEqual(get_output[0][key], value)
        for key2, value2 in self.good_output[0].items():
            self.assertTrue(bool(get_output[1][key2]))
            self.assertEqual(get_output[1][key2], value2)

    def test_get_ordered_description(self):
        get_output = self.app.get('/getDataOrdered/description/false').json
        for key, value in self.good_output[0].items():
            self.assertTrue(bool(get_output[0][key]))
            self.assertEqual(get_output[0][key], value)
        for key2, value2 in self.good_output[1].items():
            self.assertTrue(bool(get_output[1][key2]))
            self.assertEqual(get_output[1][key2], value2)

    def test_get_reverse_description(self):
        get_output = self.app.get('/getDataOrdered/description/true').json
        for key, value in self.good_output[1].items():
            self.assertTrue(bool(get_output[0][key]))
            self.assertEqual(get_output[0][key], value)
        for key2, value2 in self.good_output[0].items():
            self.assertTrue(bool(get_output[1][key2]))
            self.assertEqual(get_output[1][key2], value2)

    def test_get_ordered_accessVector(self):
        get_output = self.app.get('/getDataOrdered/accessVector/false').json
        for key, value in self.good_output[0].items():
            self.assertTrue(bool(get_output[0][key]))
            self.assertEqual(get_output[0][key], value)
        for key2, value2 in self.good_output[1].items():
            self.assertTrue(bool(get_output[1][key2]))
            self.assertEqual(get_output[1][key2], value2)

    def test_get_reverse_accessVector(self):
        get_output = self.app.get('/getDataOrdered/accessVector/true').json
        for key, value in self.good_output[1].items():
            self.assertTrue(bool(get_output[0][key]))
            self.assertEqual(get_output[0][key], value)
        for key2, value2 in self.good_output[0].items():
            self.assertTrue(bool(get_output[1][key2]))
            self.assertEqual(get_output[1][key2], value2)

    def test_get_ordered_severity(self):
        get_output = self.app.get('/getDataOrdered/severity/false').json
        for key, value in self.good_output[1].items():
            self.assertTrue(bool(get_output[0][key]))
            self.assertEqual(get_output[0][key], value)
        for key2, value2 in self.good_output[0].items():
            self.assertTrue(bool(get_output[1][key2]))
            self.assertEqual(get_output[1][key2], value2)

    def test_get_reverse_severity(self):
        get_output = self.app.get('/getDataOrdered/severity/true').json
        for key, value in self.good_output[0].items():
            self.assertTrue(bool(get_output[0][key]))
            self.assertEqual(get_output[0][key], value)
        for key2, value2 in self.good_output[1].items():
            self.assertTrue(bool(get_output[1][key2]))
            self.assertEqual(get_output[1][key2], value2)

    def test_get_ordered_metric_V2(self):
        get_output = self.app.get('/getDataOrdered/metricV2BaseScore/false').json
        for key, value in self.good_output[1].items():
            self.assertTrue(bool(get_output[0][key]))
            self.assertEqual(get_output[0][key], value)
        for key2, value2 in self.good_output[0].items():
            self.assertTrue(bool(get_output[1][key2]))
            self.assertEqual(get_output[1][key2], value2)

    def test_get_reverse_metric_V2(self):
        get_output = self.app.get('/getDataOrdered/metricV2BaseScore/true').json
        for key, value in self.good_output[0].items():
            self.assertTrue(bool(get_output[0][key]))
            self.assertEqual(get_output[0][key], value)
        for key2, value2 in self.good_output[1].items():
            self.assertTrue(bool(get_output[1][key2]))
            self.assertEqual(get_output[1][key2], value2)

    def test_get_ordered_metric_V3(self):
        get_output = self.app.get('/getDataOrdered/metricV3BaseScore/false').json
        for key, value in self.good_output[0].items():
            self.assertTrue(bool(get_output[0][key]))
            self.assertEqual(get_output[0][key], value)
        for key2, value2 in self.good_output[1].items():
            self.assertTrue(bool(get_output[1][key2]))
            self.assertEqual(get_output[1][key2], value2)

    def test_get_reverse_metric_V3(self):
        get_output = self.app.get('/getDataOrdered/metricV3BaseScore/true').json
        for key, value in self.good_output[1].items():
            self.assertTrue(bool(get_output[0][key]))
            self.assertEqual(get_output[0][key], value)
        for key2, value2 in self.good_output[0].items():
            self.assertTrue(bool(get_output[1][key2]))
            self.assertEqual(get_output[1][key2], value2)

    def test_get_ordered_publishedDate(self):
        get_output = self.app.get('/getDataOrdered/publishedDate/false').json
        for key, value in self.good_output[1].items():
            self.assertTrue(bool(get_output[0][key]))
            self.assertEqual(get_output[0][key], value)
        for key2, value2 in self.good_output[0].items():
            self.assertTrue(bool(get_output[1][key2]))
            self.assertEqual(get_output[1][key2], value2)

    def test_get_reverse_publishedDate(self):
        get_output = self.app.get('/getDataOrdered/publishedDate/true').json
        for key, value in self.good_output[0].items():
            self.assertTrue(bool(get_output[0][key]))
            self.assertEqual(get_output[0][key], value)
        for key2, value2 in self.good_output[1].items():
            self.assertTrue(bool(get_output[1][key2]))
            self.assertEqual(get_output[1][key2], value2)

    def test_get_queried(self):
        get_output = self.app.get('/getDataQuery/curl').json
        self.assertEqual(len(get_output), 1)
        for key, value in self.good_output[0].items():
            self.assertTrue(bool(get_output[0][key]))
            self.assertEqual(get_output[0][key], value)
        get_output2 = self.app.get('/getDataQuery/2011').json
        self.assertEqual(len(get_output2), 1)
        for key2, value2 in self.good_output[1].items():
            self.assertTrue(bool(get_output2[0][key2]))
            self.assertEqual(get_output2[0][key2], value2)
        get_output3 = self.app.get('/getDataQuery/AtLast').json
        self.assertEqual(len(get_output3), 0)

    def test_reset_table(self):
        get_output = self.app.get('/getDataQuery/AtLast').json
        get_output2 = self.app.get('/getData').json
        self.assertEqual(len(get_output2), 0)
        get_output3 = self.app.get('/getDataQuery/').json
        get_output4 = self.app.get('/getData').json
        self.assertNotEqual(len(get_output4), 0)
        self.assertNotEqual(len(get_output3), 0) 
        for key, value in self.good_output[0].items():
            self.assertTrue(bool(get_output3[0][key]))
            self.assertEqual(get_output3[0][key], value)
            self.assertTrue(bool(get_output4[0][key]))
            self.assertEqual(get_output4[0][key], value)
        for key2, value2 in self.good_output[1].items():
            self.assertTrue(bool(get_output3[1][key2]))
            self.assertEqual(get_output3[1][key2], value2)
            self.assertTrue(bool(get_output4[1][key2]))
            self.assertEqual(get_output4[1][key2], value2)


if __name__ == '__main__':
    unittest.main()
