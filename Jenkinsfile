#!/usr/bin/env groovy

@Library('sd')_
def kubeLabel = getKubeLabel()

pipeline {

  agent {
      kubernetes {
        label "${kubeLabel}"
        cloud 'Kube mwdevel'
        defaultContainer 'runner'
        inheritFrom 'ci-template'
        containerTemplate {
          name 'runner'
          image 'italiangrid/voms-build-centos7:015edee'
          ttyEnabled true
          command 'cat'
        }
      }
  }

  options {
    timeout(time: 10, unit: 'MINUTES')
    buildDiscarder(logRotator(numToKeepStr: '5'))
  }

  triggers { cron('@daily') }

  stages {
    stage ('build') {
      steps {
          sh "./autogen.sh"
          sh "./configure && make"
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
