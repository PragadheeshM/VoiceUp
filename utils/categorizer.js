const { GoogleGenerativeAI } = require('@google/generative-ai');
require('dotenv').config();

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

async function categorizeComplaint(description) {
    try {
        const model = genAI.getGenerativeModel({
            model: "gemini-2.0-flash",
            generationConfig: {
                temperature: 0.2,
                topK: 1,
                topP: 0.95,
                maxOutputTokens: 10,
            }
        });

        const prompt = `Analyze this complaint and categorize it into exactly one of these departments: MUNICIPALITY, POLICE, ELECTRICITY, or RTO.
        
        Rules for categorization:
        - MUNICIPALITY: For issues related to roads, garbage, water supply, drainage, public spaces, and city infrastructure
        - POLICE: For issues related to law enforcement, public safety, traffic violations, and security concerns
        - ELECTRICITY: For issues related to power supply, street lights, electrical infrastructure, and power outages
        - RTO: For issues related to vehicle registration, driving licenses, traffic management, and transport regulations
        
        Only respond with the department name in uppercase. Here's the complaint description: ${description}`;

        const result = await model.generateContent(prompt);
        const response = await result.response;
        const category = response.text().trim();

        // Validate the response
        const validCategories = ['MUNICIPALITY', 'POLICE', 'ELECTRICITY', 'RTO'];
        if (!validCategories.includes(category)) {
            throw new Error('Invalid category returned from AI');
        }

        return category;
    } catch (error) {
        console.error('Error in categorization:', error);
        throw error;
    }
}

module.exports = {
    categorizeComplaint
}; 