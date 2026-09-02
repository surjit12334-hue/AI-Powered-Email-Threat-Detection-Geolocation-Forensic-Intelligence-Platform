document.addEventListener('DOMContentLoaded', function () {
    const uploadZone = document.getElementById('uploadZone');
    const fileInput = document.getElementById('fileInput');
    const browseBtn = document.getElementById('browseBtn');
    const analyzeBtn = document.getElementById('analyzeBtn');
    const fileInfo = document.getElementById('fileInfo');
    const fileName = document.getElementById('fileName');
    const fileSize = document.getElementById('fileSize');
    const removeFile = document.getElementById('removeFile');
    const loadingOverlay = document.getElementById('loadingOverlay');
    const analysisSteps = document.getElementById('analysisSteps');

    let selectedFile = null;

    browseBtn.addEventListener('click', () => fileInput.click());
    uploadZone.addEventListener('click', (e) => {
        if (e.target === uploadZone || e.target.closest('.upload-icon') || e.target.tagName === 'H3' || e.target.tagName === 'P') {
            fileInput.click();
        }
    });

    uploadZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadZone.classList.add('dragover');
    });

    uploadZone.addEventListener('dragleave', () => {
        uploadZone.classList.remove('dragover');
    });

    uploadZone.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadZone.classList.remove('dragover');
        const files = e.dataTransfer.files;
        if (files.length > 0) handleFile(files[0]);
    });

    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) handleFile(e.target.files[0]);
    });

    removeFile.addEventListener('click', (e) => {
        e.stopPropagation();
        selectedFile = null;
        fileInput.value = '';
        fileInfo.style.display = 'none';
        analyzeBtn.disabled = true;
    });

    function handleFile(file) {
        if (!file.name.endsWith('.eml')) {
            alert('Please select a .eml file');
            return;
        }
        selectedFile = file;
        fileName.textContent = file.name;
        fileSize.textContent = `(${(file.size / 1024).toFixed(1)} KB)`;
        fileInfo.style.display = 'flex';
        analyzeBtn.disabled = false;
    }

    analyzeBtn.addEventListener('click', async () => {
        if (!selectedFile) return;

        loadingOverlay.style.display = 'flex';
        analyzeBtn.disabled = true;

        const steps = [
            'Parsing email file...',
            'Extracting headers...',
            'Analyzing URLs...',
            'Analyzing IP addresses...',
            'Checking authentication...',
            'Running AI classification...',
            'Calculating threat score...',
        ];

        analysisSteps.innerHTML = '';
        steps.forEach((step, i) => {
            const div = document.createElement('div');
            div.className = 'analysis-step';
            div.textContent = step;
            div.id = `step-${i}`;
            analysisSteps.appendChild(div);
        });

        let stepIndex = 0;
        const stepInterval = setInterval(() => {
            if (stepIndex > 0) {
                document.getElementById(`step-${stepIndex - 1}`).className = 'analysis-step done';
                document.getElementById(`step-${stepIndex - 1}`).innerHTML =
                    `<i class="fas fa-check-circle"></i> ${steps[stepIndex - 1]}`;
            }
            if (stepIndex < steps.length) {
                document.getElementById(`step-${stepIndex}`).className = 'analysis-step active';
                document.getElementById(`step-${stepIndex}`).innerHTML =
                    `<i class="fas fa-spinner fa-spin"></i> ${steps[stepIndex]}`;
                stepIndex++;
            }
        }, 400);

        const formData = new FormData();
        formData.append('email_file', selectedFile);

        try {
            const response = await fetch('/api/upload', {
                method: 'POST',
                body: formData,
            });

            const data = await response.json();

            if (data.error) {
                alert('Error: ' + data.error);
                loadingOverlay.style.display = 'none';
                analyzeBtn.disabled = false;
                clearInterval(stepInterval);
                return;
            }

            // Mark all steps done
            clearInterval(stepInterval);
            steps.forEach((step, i) => {
                const el = document.getElementById(`step-${i}`);
                if (el) {
                    el.className = 'analysis-step done';
                    el.innerHTML = `<i class="fas fa-check-circle"></i> ${step}`;
                }
            });

            setTimeout(() => {
                window.location.href = `/dashboard?case_id=${data.case_id}`;
            }, 800);

        } catch (err) {
            alert('Upload failed: ' + err.message);
            loadingOverlay.style.display = 'none';
            analyzeBtn.disabled = false;
            clearInterval(stepInterval);
        }
    });
});
