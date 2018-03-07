pipeline {
  agent any
  stages {
    stage('Build') {
      steps {
        sh 'make build_caddy_image'
        sh 'make run_unit_tests'
      }
    }
    stage('Integ') {
      steps {
        sh 'docker images'
        sh 'make run_integration_tests'
      }
    }
  }
}
