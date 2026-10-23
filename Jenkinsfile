pipeline {
    agent any

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
                sh '. .venv/bin/activate && pytest --cov=src --cov-branch --cov-report=term-missing'
            }
        }
    }
}
