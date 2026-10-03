const fs = require('fs');
const path = require('path');

class TestFileGenerator {
    constructor() {
        this.testDir = path.join(__dirname, 'test-files');
        this.ensureTestDirectory();
    }

    ensureTestDirectory() {
        if (!fs.existsSync(this.testDir)) {
            fs.mkdirSync(this.testDir, { recursive: true });
            console.log('✅ Created test-files directory');
        }
    }

    // Generate random content of specific size
    generateRandomContent(sizeInBytes) {
        const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
        let content = '';
        const charsetLength = charset.length;
        
        for (let i = 0; i < sizeInBytes; i++) {
            content += charset.charAt(Math.floor(Math.random() * charsetLength));
        }
        return content;
    }

    // Create test files of various sizes
    async createTestFiles() {
        const fileSizes = [
            { size: 10 * 1024, name: '10KB' },        // 10KB
            { size: 50 * 1024, name: '50KB' },        // 50KB  
            { size: 100 * 1024, name: '100KB' },      // 100KB
            { size: 250 * 1024, name: '250KB' },      // 250KB
            { size: 1024 * 1024, name: '1MB' },       // 1MB
            { size: 2 * 1024 * 1024, name: '2MB' },   // 2MB
            { size: 5 * 1024 * 1024, name: '5MB' },   // 5MB
            { size: 10 * 1024 * 1024, name: '10MB' }, // 10MB
        ];

        console.log('📁 Creating test files...');
        
        for (const fileSpec of fileSizes) {
            const filename = `test_${fileSpec.name}_evidence.dat`;
            const filepath = path.join(this.testDir, filename);
            
            const content = this.generateRandomContent(fileSpec.size);
            fs.writeFileSync(filepath, content);
            
            // Verify file size
            const stats = fs.statSync(filepath);
            console.log(`✅ Created ${filename} - ${(stats.size / 1024).toFixed(2)} KB`);
        }

        console.log('🎉 All test files created successfully!');
        return this.getTestFilesList();
    }

    getTestFilesList() {
        const files = fs.readdirSync(this.testDir);
        return files.map(filename => {
            const filepath = path.join(this.testDir, filename);
            const stats = fs.statSync(filepath);
            return {
                filename: filename,
                path: filepath,
                size: stats.size,
                sizeKB: (stats.size / 1024).toFixed(2)
            };
        });
    }
}

// Run if called directly
if (require.main === module) {
    const generator = new TestFileGenerator();
    generator.createTestFiles().then(fileList => {
        console.log('\n📊 Test Files Summary:');
        fileList.forEach(file => {
            console.log(`   ${file.filename}: ${file.sizeKB} KB`);
        });
    });
}

module.exports = TestFileGenerator;