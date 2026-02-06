document.addEventListener('DOMContentLoaded', () => {
    // Smooth scrolling for navigation links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            document.querySelector(this.getAttribute('href')).scrollIntoView({
                behavior: 'smooth'
            });
        });
    });

    // API Key Button
    document.getElementById('apiKeyBtn').addEventListener('click', () => {
        const modal = createModal('Get API Key', `
            <form id="apiKeyForm" method="POST" action="/register">
                <div class="form-group">
                    <label for="email">Email Address:</label>
                    <input type="email" id="email" name="email" required>
                </div>
                <div class="form-group">
                    <label for="purpose">Purpose (Optional):</label>
                    <textarea id="purpose" name="purpose"></textarea>
                </div>
                <button type="submit" class="submit-btn">Get API Key</button>
            </form>
        `);
        
        document.getElementById('apiKeyForm').addEventListener('submit', (e) => {
            e.preventDefault();
            const form = e.target;
            const formData = new FormData(form);
            
            // Submit the form data to /register
            fetch('/register', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                alert('API key request submitted. You will receive your key via email.');
                modal.remove();
            })
            .catch(error => {
                alert('Error submitting request. Please try again.');
                console.error('Error:', error);
            });
        });
    });

    // Report IP Button
    document.getElementById('reportIpBtn').addEventListener('click', () => {
        const modal = createModal('Report Abusive IP', `
            <form id="reportIpForm" method="POST" action="/report">
                <div class="form-group">
                    <label for="ip">IP Address:</label>
                    <input type="text" id="ip" name="ip" required>
                    <small class="help-text">Enter a valid public IPv4 or IPv6 address</small>
                </div>
                <div class="form-group">
                    <label for="reason">Reason for Report (Optional):</label>
                    <textarea id="reason" name="reason"></textarea>
                </div>
                <button type="submit" class="submit-btn">Submit Report</button>
            </form>
        `);
        
        const ipInput = modal.querySelector('#ip');
        ipInput.addEventListener('input', (e) => validatePublicIP(e));
        
        modal.querySelector('#reportIpForm').addEventListener('submit', (e) => {
            e.preventDefault();
            if (!validatePublicIP({ target: ipInput })) {
                return;
            }
            const form = e.target;
            const formData = new FormData(form);
            
            // Submit the form data to /report
            fetch('/report', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                alert('IP report submitted. Thank you for your contribution!');
                modal.remove();
            })
            .catch(error => {
                alert('Error submitting report. Please try again.');
                console.error('Error:', error);
            });
        });
    });

    // Scan Button
    document.getElementById('scanBtn').addEventListener('click', () => {
        const modal = createModal('Security Scan', `
            <form id="scanForm" method="POST" action="/scan">
                <div class="form-group">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" required>
                </div>
                <div class="form-group">
                    <label for="target">Target IP CIDR (default /32):</label>
                    <input type="text" id="target" name="target" required>
                    <small class="help-text">Enter a single IP (e.g., 192.168.1.1) or CIDR range (e.g., 192.168.1.0/24)</small>
                </div>
                <div class="form-group">
                    <label for="scanType">Scan Type:</label>
                    <select id="scanType" name="scan_type" required>
                        <option value="snow">Snow Scan</option>
                    </select>
                </div>
                <button type="submit" class="submit-btn">Add to Queue</button>
            </form>
        `);
        
        const targetInput = modal.querySelector('#target');
        targetInput.addEventListener('input', (e) => validateCIDR(e));
        
        modal.querySelector('#scanForm').addEventListener('submit', (e) => {
            e.preventDefault();
            if (!validateCIDR({ target: targetInput })) {
                return;
            }
            const form = e.target;
            const formData = new FormData(form);
            
            // Submit the form data to /scan
            fetch('/scan', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                alert('Target added to scan queue. Results will be available shortly.');
                modal.remove();
            })
            .catch(error => {
                alert('Error submitting scan request. Please try again.');
                console.error('Error:', error);
            });
        });
    });
});

function validatePublicIP(event) {
    const input = event.target;
    const value = input.value.trim();
    
    // Check if it's IPv4
    if (isIPv4(value)) {
        if (isPrivateIPv4(value)) {
            input.setCustomValidity('Private IPv4 addresses are not allowed');
            return false;
        }
        if (isReservedIPv4(value)) {
            input.setCustomValidity('Reserved IPv4 addresses are not allowed');
            return false;
        }
        if (isLoopbackIPv4(value)) {
            input.setCustomValidity('Loopback IPv4 addresses are not allowed');
            return false;
        }
        input.setCustomValidity('');
        return true;
    }
    
    // Check if it's IPv6
    if (isIPv6(value)) {
        if (isPrivateIPv6(value)) {
            input.setCustomValidity('Private IPv6 addresses are not allowed');
            return false;
        }
        if (isReservedIPv6(value)) {
            input.setCustomValidity('Reserved IPv6 addresses are not allowed');
            return false;
        }
        if (isLoopbackIPv6(value)) {
            input.setCustomValidity('Loopback IPv6 addresses are not allowed');
            return false;
        }
        input.setCustomValidity('');
        return true;
    }
    
    input.setCustomValidity('Please enter a valid public IPv4 or IPv6 address');
    return false;
}

function isIPv4(ip) {
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!ipv4Regex.test(ip)) return false;
    
    const parts = ip.split('.');
    return parts.every(part => {
        const num = parseInt(part);
        return num >= 0 && num <= 255;
    });
}

function isIPv6(ip) {
    const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){1,7}:|^([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}$|^([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}$|^([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}$|^([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}$|^[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})$|^:((:[0-9a-fA-F]{1,4}){1,7}|:)$/;
    return ipv6Regex.test(ip);
}

function isPrivateIPv4(ip) {
    const parts = ip.split('.').map(Number);
    
    // Check for private IP ranges
    return (
        // 10.0.0.0/8
        (parts[0] === 10) ||
        // 172.16.0.0/12
        (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
        // 192.168.0.0/16
        (parts[0] === 192 && parts[1] === 168) ||
        // 169.254.0.0/16 (Link-local)
        (parts[0] === 169 && parts[1] === 254)
    );
}

function isReservedIPv4(ip) {
    const parts = ip.split('.').map(Number);
    
    return (
        // 0.0.0.0/8
        (parts[0] === 0) ||
        // 127.0.0.0/8 (Loopback)
        (parts[0] === 127) ||
        // 224.0.0.0/4 (Multicast)
        (parts[0] >= 224 && parts[0] <= 239) ||
        // 240.0.0.0/4 (Reserved)
        (parts[0] >= 240) ||
        // 100.64.0.0/10 (Carrier-grade NAT)
        (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127)
    );
}

function isLoopbackIPv4(ip) {
    const parts = ip.split('.').map(Number);
    return parts[0] === 127;
}

function isPrivateIPv6(ip) {
    return (
        // fc00::/7 (Unique Local Addresses)
        ip.startsWith('fc') ||
        ip.startsWith('fd') ||
        // fe80::/10 (Link-local)
        ip.startsWith('fe8') ||
        ip.startsWith('fe9') ||
        ip.startsWith('fea') ||
        ip.startsWith('feb')
    );
}

function isReservedIPv6(ip) {
    return (
        // ::/128 (Unspecified)
        ip === '::' ||
        // ff00::/8 (Multicast)
        ip.startsWith('ff') ||
        // 2001:db8::/32 (Documentation)
        ip.startsWith('2001:db8')
    );
}

function isLoopbackIPv6(ip) {
    return ip === '::1';
}

function validateCIDR(event) {
    const input = event.target;
    const value = input.value.trim();
    
    // Check if it's IPv4 with optional CIDR
    if (isIPv4(value.split('/')[0])) {
        const ip = value.split('/')[0];
        if (isPrivateIPv4(ip)) {
            input.setCustomValidity('Private IPv4 addresses are not allowed');
            return false;
        }
        if (isReservedIPv4(ip)) {
            input.setCustomValidity('Reserved IPv4 addresses are not allowed');
            return false;
        }
        if (isLoopbackIPv4(ip)) {
            input.setCustomValidity('Loopback IPv4 addresses are not allowed');
            return false;
        }
        
        // Validate CIDR if present
        if (value.includes('/')) {
            const cidr = parseInt(value.split('/')[1]);
            if (cidr < 0 || cidr > 32) {
                input.setCustomValidity('IPv4 CIDR must be between 0 and 32');
                return false;
            }
        }
        
        input.setCustomValidity('');
        return true;
    }
    
    // Check if it's IPv6 with optional CIDR
    if (isIPv6(value.split('/')[0])) {
        const ip = value.split('/')[0];
        if (isPrivateIPv6(ip)) {
            input.setCustomValidity('Private IPv6 addresses are not allowed');
            return false;
        }
        if (isReservedIPv6(ip)) {
            input.setCustomValidity('Reserved IPv6 addresses are not allowed');
            return false;
        }
        if (isLoopbackIPv6(ip)) {
            input.setCustomValidity('Loopback IPv6 addresses are not allowed');
            return false;
        }
        
        // Validate CIDR if present
        if (value.includes('/')) {
            const cidr = parseInt(value.split('/')[1]);
            if (cidr < 0 || cidr > 128) {
                input.setCustomValidity('IPv6 CIDR must be between 0 and 128');
                return false;
            }
        }
        
        input.setCustomValidity('');
        return true;
    }
    
    input.setCustomValidity('Please enter a valid public IPv4 or IPv6 address with optional CIDR notation');
    return false;
}

function createModal(title, content) {
    const modal = document.createElement('div');
    modal.style.cssText = `
        position: fixed;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        background: white;
        padding: 2rem;
        border-radius: 10px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        z-index: 1000;
        min-width: 300px;
        max-width: 500px;
    `;
    
    modal.innerHTML = `
        <h3 style="margin-bottom: 1rem; color: #2c3e50;">${title}</h3>
        ${content}
        <button onclick="this.parentElement.remove()" style="
            position: absolute;
            top: 1rem;
            right: 1rem;
            background: none;
            border: none;
            font-size: 1.5rem;
            cursor: pointer;
            color: #666;
        ">&times;</button>
    `;
    
    // Add styles for form elements
    const style = document.createElement('style');
    style.textContent = `
        .form-group {
            margin-bottom: 1rem;
        }
        .form-group label {
            display: block;
            margin-bottom: 0.5rem;
            color: #2c3e50;
        }
        .form-group input,
        .form-group textarea,
        .form-group select {
            width: 100%;
            padding: 0.5rem;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 1rem;
        }
        .form-group textarea {
            height: 100px;
            resize: vertical;
        }
        .submit-btn {
            background-color: #3498db;
            color: white;
            border: none;
            padding: 0.8rem 1.5rem;
            border-radius: 5px;
            cursor: pointer;
            width: 100%;
            font-size: 1rem;
            margin-top: 1rem;
        }
        .submit-btn:hover {
            background-color: #2980b9;
        }
        .help-text {
            display: block;
            margin-top: 0.25rem;
            color: #666;
            font-size: 0.875rem;
        }
    `;
    document.head.appendChild(style);
    
    document.body.appendChild(modal);
    return modal;
}

// Add scroll-based animations
window.addEventListener('scroll', () => {
    const sections = document.querySelectorAll('section');
    sections.forEach(section => {
        const sectionTop = section.getBoundingClientRect().top;
        const windowHeight = window.innerHeight;
        
        if (sectionTop < windowHeight * 0.75) {
            section.style.opacity = '1';
            section.style.transform = 'translateY(0)';
        }
    });
}); 
