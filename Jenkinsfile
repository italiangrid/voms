#!/usr/bin/env groovy

pipeline {

  agent {
    kubernetes {
      cloud 'Kube mwdevel'
        label 'build'
        containerTemplate {
          name 'builder'
            image 'voms/voms-build:centos6'
            ttyEnabled true
            command 'cat'
        }
    }
  }

  options {
    timeout(time: 1, unit: 'HOURS')
    buildDiscarder(logRotator(numToKeepStr: '5'))
  }

  stages {
    stage ('build') {
      steps {
        container('builder') {
          sh "./autogen.sh"
          sh "./configure && make"
        }
      }
    }

    stage('result'){
      steps {
        script {
          currentBuild.result = 'SUCCESS'
        }
      }
    }
  }
  
  post {

    failure {
      slackSend color: 'danger', message: "${env.JOB_NAME} - #${env.BUILD_NUMBER} Failure (<${env.BUILD_URL}|Open>)"
    }
    
    changed {
      script{
        if('SUCCESS'.equals(currentBuild.result)) {
          slackSend color: 'good', message: "${env.JOB_NAME} - #${env.BUILD_NUMBER} Back to normal (<${env.BUILD_URL}|Open>)"
        }
      }
    } 
  }
}
