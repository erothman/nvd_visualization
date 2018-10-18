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
            $scope.dataEntry = x;
            $scope.showEntry = true;
        }
        $scope.hideEntry = function() {
            $scope.showEntry = false;
        }
/*        $scope.openModalData = function(x) {
            $log.log(x)
            var modalInstance = $uibModal.open({
              templateUrl: '../templates/modal.html',
              controller: 'ModalInstanceCtrl',
              size: 'lg',
              resolve: {
                data: function () {
                  return x;
                }
              }
            });
        }*/
}]);

/*angular.module('VulnerabilityTableApp').controller('ModalInstanceCtrl', function ($uibModalInstance, data) {
  var modal = this;
  modal.data = data;
  
  modal.exit = function () {
    $uibModalInstance.close();
  };
});*/
}());
