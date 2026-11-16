pipeline {
    agent any

    environment {
        IMAGE_NAME = 'pocket-packet-sniffer'
        IMAGE_TAG  = "${env.BUILD_NUMBER}"
    }

    stages {
        stage('Install') {
            steps {
                sh 'python3 -m venv .venv'
                sh '. .venv/bin/activate && pip install --upgrade pip && pip install -r requirements.txt'
            }
        }
        stage('Lint') {
            steps {
                sh '. .venv/bin/activate && flake8 src tests --count --select=E9,F63,F7,F82 --show-source --statistics'
            }
        }
        stage('Security Scan') {
            steps {
                sh '. .venv/bin/activate && bandit -r src'
                sh '. .venv/bin/activate && pip-audit -r requirements.txt'
            }
        }
        stage('Test') {
            steps {
                sh 'mkdir -p reports'
                sh '''. .venv/bin/activate && pytest \
                    --cov=src --cov-branch --cov-report=term-missing \
                    --cov-report=xml:reports/coverage.xml \
                    --junitxml=reports/unit_tests.xml'''
            }
            post {
                always {
                    junit 'reports/unit_tests.xml'
                    archiveArtifacts artifacts: 'reports/*.xml', allowEmptyArchive: true
                }
            }
        }
        stage('Docker Build') {
            steps {
                sh 'docker build -t ${IMAGE_NAME}:${IMAGE_TAG} -t ${IMAGE_NAME}:latest .'
            }
        }
        // Continuous deployment: only builds of main are deployed to the target host
        stage('Deploy') {
            when {
                branch 'main'
            }
            steps {
                sh 'docker compose up -d --build dashboard'
            }
        }
        stage('Smoke Test') {
            when {
                branch 'main'
            }
            steps {
                // NFR-PORT-01: the service must be up within 15 seconds
                sh '''
                    for i in $(seq 1 15); do
                        if curl -fsS http://localhost:8000/health; then
                            echo "Dashboard healthy after ${i}s"
                            exit 0
                        fi
                        sleep 1
                    done
                    echo "Dashboard did not become healthy within 15s"
                    docker compose logs dashboard
                    exit 1
                '''
            }
        }
    }

    post {
        always {
            sh 'docker image prune -f || true'
        }
    }
}
