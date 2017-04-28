(function(window, undefined) {'use strict';


angular.module('DevopsDashboard.widget.virustotal', ['adf.provider', 'angularFileUpload'])
  .value('virusTotalUrl', '/proxy/https://www.virustotal.com/vtapi/v2')
  .config(["dashboardProvider", function(dashboardProvider){
    dashboardProvider
      .widget('virustotal', {
        title: 'VirusTotal',
        description: 'VirusTotal API Interface',
        authorizedGroups: ['root9B root9b_all'],
        controller: 'virusTotalCtrl',
        templateUrl: '{widgetsPath}/virustotal/src/view.html',
        edit: {
          templateUrl: '{widgetsPath}/virustotal/src/edit.html'
        }
      });
  }])
  .service('virusTotalService', ["$q", "$http", "virusTotalUrl", function($q, $http, virusTotalUrl) {
    return {
      ipReport: function(virusTotalApiKey, ip) {
        var url = virusTotalUrl + '/ip-address/report';

        var config = {
          params: {
            apikey: virusTotalApiKey,
            ip: ip
          }
        };
        return $http.get(url, config);
      },
      domainReport: function(virusTotalApiKey, domain) {
        var url = virusTotalUrl + '/domain/report';

        var config = {
          params: {
            apikey: virusTotalApiKey,
            domain: domain
          }
        };
        return $http.get(url, config);
      },
      urlScan: function(virusTotalApiKey, scanUrl) {
        var url = virusTotalUrl + '/url/report';

        var config = {
          headers : {
              'Content-Type': 'application/x-www-form-urlencoded;charset=utf-8;'
          }
        }

        var data = $.param({
          apikey: virusTotalApiKey,
          resource: scanUrl,
          scan: 1
        });

        return $http.post(url, data, config);
      }
    };
  }])
  .controller('virusTotalCtrl', ["$scope", "$http", "config", "virusTotalUrl", "virusTotalService", "FileUploader", "Logger", function($scope, $http, config, virusTotalUrl, virusTotalService, FileUploader, Logger){
    $scope.virusTotalUrl = virusTotalUrl;
    $scope.output = '';
    $scope.domain = 'root9b.com';
    $scope.url = 'http://www.root9b.com';
    $scope.ip = '107.170.97.60';
    $scope.upload_progress = null;

    var logger = Logger;

    /* File Scanner */
    var uploader = $scope.uploader = new FileUploader({formData: [{apikey: config.apikey}]});

    uploader.onWhenAddingFileFailed = function(item /*{File|FileLikeObject}*/, filter, options) {
        console.info('onWhenAddingFileFailed', item, filter, options);
    };

    uploader.onAfterAddingFile = function(fileItem) {
        fileItem.upload();
        $scope.upload_progress = 0;
    };
    uploader.onProgressItem = function(fileItem, progress) {
        $scope.upload_progress = progress;
    };
    uploader.onSuccessItem = function(fileItem, response, status, headers) {
        $scope.output = response;
        logger.info({service: 'VirusTotal', command: 'fileScan', data: response});
        $scope.upload_progress = null;
    };
    uploader.onErrorItem = function(fileItem, response, status, headers) {
        console.info('onErrorItem', fileItem, response, status, headers);
        logger.error({service: 'VirusTotal', command: 'fileScan', data: response});
        $scope.upload_progress = null;
    };

    /* Domain Report */
    $scope.domainReport = function() {
      if (!config.apikey) {
          /* Error: Missing API Key */
          $scope.output = 'Missing API Key. See Widget settings.';
          logger.error({service: 'VirusTotal', command: 'domainReport', data: 'Missing API Key. See Widget settings.'});
          return;
      }

      var promise = virusTotalService.domainReport(config.apikey, $scope.domain);
      promise.then(function(response) {
        /* Success */
        $scope.output = response.data;
        logger.info({service: 'VirusTotal', command: 'domainReport', data: response.data});
      }, function(reason) {
        /* Failed */
        $scope.output = reason;
        logger.error({service: 'VirusTotal', command: 'domainReport', data: reason});
      });
    }

    /* URL Scanner */
    $scope.urlScan = function() {
      if (!config.apikey) {
          /* Error: Missing API Key */
          $scope.output = 'Missing API Key. See Widget settings.';
          logger.error({service: 'VirusTotal', command: 'urlScan', data: 'Missing API Key. See Widget settings.'});
          return;
      }

      var promise = virusTotalService.urlScan(config.apikey, $scope.url);
      promise.then(function(response) {
        /* Success */
        $scope.output = response.data;
      }, function(reason) {
        /* Failed */
        $scope.output = reason;
        logger.error({service: 'VirusTotal', command: 'urlScan', data: reason});
      });
    }

    /* IP Report */
    $scope.ipReport = function() {
      if (!config.apikey) {
          /* Error: Missing API Key */
          $scope.output = 'Missing API Key. See Widget settings.';
          logger.error({service: 'VirusTotal', command: 'ipReport', data: 'Missing API Key. See Widget settings.'});
          return;
      }

      var promise = virusTotalService.ipReport(config.apikey, $scope.ip);
      promise.then(function(response) {
        /* Success */
        console.log('Success: ', response);
        $scope.output = response.data;
      }, function(reason) {
        /* Failed */
        console.log('Failed: ', reason);
        $scope.output = reason;
        logger.error({service: 'VirusTotal', command: 'ipReport', data: reason});
      });
    }

  }])

angular.module("DevopsDashboard.widget.virustotal").run(["$templateCache", function($templateCache) {$templateCache.put("{widgetsPath}/virustotal/src/edit.html","<form role=form><div class=form-group><label for=apikey>VirusTotal API Key</label> <input type=text class=form-control id=apikey ng-model=config.apikey placeholder=\"Enter VirusTotal API Key\"></div></form>");
$templateCache.put("{widgetsPath}/virustotal/src/view.html","<style>\n    .my-drop-zone { border: dotted 3px lightgray; }\n    .nv-file-over { border: dotted 3px red; } /* Default class applied to drop zones on over */\n    .another-file-over-class { border: dotted 3px green; }\n    html, body { height: 100%; }\n</style><div><label for=domain>Domain Report</label><form role=form><div class=form-group><input type=text class=form-control id=domain ng-model=domain placeholder=\"Enter a domain\"> <button ng-click=domainReport()>Submit</button></div></form><label for=domain>IP Scan</label><form role=form><div class=form-group><input type=text class=form-control id=ip ng-model=ip placeholder=\"Enter an IP Address\"> <button ng-click=ipReport()>Submit</button></div></form><label for=url>URL Scan</label><form role=form><div class=form-group><input type=text class=form-control id=url ng-model=url placeholder=\"Enter a url\"> <button ng-click=urlScan()>Submit</button></div></form><label for=upload>File Upload</label> <input id=upload type=file nv-file-select uploader=uploader options=\"{ url: \'{{virusTotalUrl}}/file/scan\' }\"><br><div nv-file-drop uploader=uploader options=\"{ url: \'{{virusTotalUrl}}/file/scan\' }\"><div nv-file-over uploader=uploader over-class=another-file-over-class class=\"well my-drop-zone\">Drop a file here to scan</div></div><div ng-if=upload_progress class=progress><div class=\"progress-bar progress-bar-info progress-bar-striped active\" role=progressbar aria-valuenow={{upload_progress}} aria-valuemin=0 aria-valuemax=100 style=\"width: {{upload_progress}}%\"><span class=sr-only>{{upload_progress}}% Complete</span></div></div><pre>{{output | json}}</pre></div>");}]);})(window);