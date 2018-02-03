pipeline {
  agent any
  stages {
    stage('Build') {
      steps {
        sh 'git submodule update --init --recursive'
        sh 'git submodule update --recursive --remote'
        sh 'make build_caddy_image'
        sh 'make run_unit_tests'
      }
    }
  }
}
