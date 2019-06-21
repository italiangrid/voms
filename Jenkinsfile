#!/usr/bin/env groovy

pipeline {

  agent {
      kubernetes {
          label "voms-${env.JOB_BASE_NAME}-${env.BUILD_NUMBER}"
          cloud 'Kube mwdevel'
          defaultContainer 'jnlp'
          inheritFrom 'ci-template'
          containerTemplate {
            name 'runner'
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

  triggers { cron('@daily') }

  stages {
    stage ('build') {
      steps {
        container('runner') {
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
