document.addEventListener('DOMContentLoaded', () => {
    const dropZone = document.getElementById('drop-zone');
    const fileInput = document.getElementById('file-input');
    const browseBtn = document.getElementById('browse-btn');
    const fileNameDisplay = document.getElementById('file-name-display');
    const progressContainer = document.getElementById('upload-progress-container');
    const progressBar = document.getElementById('upload-progress-bar');
    const errorDisplay = document.getElementById('upload-error');
    const uploadActions = document.getElementById('upload-actions');
    const btnUploadAnother = document.getElementById('btn-upload-another');
    const reportContainer = document.getElementById('report-container');

    function resetUpload() {
        fileInput.value = '';
        fileNameDisplay.textContent = '';
        progressContainer.style.display = 'none';
        progressBar.style.width = '0%';
        errorDisplay.style.display = 'none';
        uploadActions.style.display = 'none';
        dropZone.style.display = 'block';
        reportContainer.style.display = 'none';
        
        if (window.charts) {
            for (let c in window.charts) {
                if (window.charts[c]) window.charts[c].destroy();
            }
        }
    }

    btnUploadAnother.addEventListener('click', resetUpload);

    browseBtn.addEventListener('click', () => fileInput.click());

    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            handleFile(e.target.files[0]);
        }
    });

    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('drag-over');
    });

    dropZone.addEventListener('dragleave', (e) => {
        e.preventDefault();
        dropZone.classList.remove('drag-over');
    });

    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('drag-over');
        if (e.dataTransfer.files.length > 0) {
            handleFile(e.dataTransfer.files[0]);
        }
    });

    function handleFile(file) {
        errorDisplay.style.display = 'none';
        
        if (!file.name.toLowerCase().endsWith('.csv')) {
            showError('File must be a .csv');
            return;
        }

        const maxMB = 50; 
        if (file.size > maxMB * 1024 * 1024) {
            showError(`File size exceeds ${maxMB}MB limit`);
            return;
        }

        fileNameDisplay.textContent = `${file.name} (${(file.size / 1024 / 1024).toFixed(2)} MB)`;
        uploadFile(file);
    }

    function showError(msg) {
        errorDisplay.textContent = msg;
        errorDisplay.style.display = 'block';
        progressContainer.style.display = 'none';
    }

    function uploadFile(file) {
        progressContainer.style.display = 'block';
        progressBar.style.width = '0%';

        const formData = new FormData();
        formData.append('file', file);

        const xhr = new XMLHttpRequest();
        xhr.open('POST', '/upload', true);
        
        xhr.upload.onprogress = (e) => {
            if (e.lengthComputable) {
                const percent = (e.loaded / e.total) * 100;
                progressBar.style.width = percent + '%';
            }
        };

        xhr.onload = () => {
            if (xhr.status >= 200 && xhr.status < 300) {
                progressBar.style.width = '100%';
                setTimeout(() => {
                    dropZone.style.display = 'none';
                    uploadActions.style.display = 'block';
                    reportContainer.style.display = 'block';
                    const json = JSON.parse(xhr.responseText);
                    if (window.renderReport) {
                        window.renderReport(json);
                    }
                }, 500);
            } else {
                try {
                    const res = JSON.parse(xhr.responseText);
                    showError(res.error || 'Upload failed');
                } catch {
                    showError('Upload failed');
                }
            }
        };

        xhr.onerror = () => {
            showError('Connection error — is the server running?');
        };

        xhr.send(formData);
    }
});
