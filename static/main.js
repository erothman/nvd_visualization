(function () {
  'use strict';
  var app = angular.module('VulnerabilityTableApp', []);

  app.controller('TableCtrl', ['$scope', '$log', '$http', function($scope, $log, $http) {
        var $ctrl = this;
        $http.get('/getData')
        .then(function (response) {
            $scope.vulnerabilities = response.data;
        });
        $scope.reverse = false;
        $scope.alphField = "test";
        $scope.queryTerm = "";
        $scope.showEntry = false;
        $scope.dataEntry = "";
        $scope.getOrganizedData = function(field) {
            $log.log(field)
            if ($scope.alphField == field) {
                $scope.reverse = !$scope.reverse;
            } else {$scope.reverse = false; $scope.alphField = field;}
            $log.log($scope.alphField)
            $http.get('/getDataOrdered/'+field+'/'+$scope.reverse)
            .then(function (response) {
                $scope.vulnerabilities = response.data;
            });
        }
        $scope.getQueriedData = function() {
            $http.get('/getDataQuery/'+$scope.queryTerm)
            .then(function (response) {
                $scope.vulnerabilities = response.data;
            });
        }
        $scope.selectEntry = function(x) {
            $scope.dataEntry = x;//angular.toJson(x);
            $scope.showEntry = true;
        }
        $scope.hideEntry = function() {
            $scope.showEntry = false;
        }
        $scope.goToTop = function() {
            document.body.scrollTop = 0;
            document.documentElement.scrollTop = 0;
        }
}]);
}());
