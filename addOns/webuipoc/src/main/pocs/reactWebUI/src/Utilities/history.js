import axios from 'axios';

const sendHistory = async () => {
    try {
            const response = await axios.get('/OTHER/exim/other/exportHar/');
            return response.data;
        } 
  catch (error) {
        console.error('Error fetching data:', error);
        throw error;
    }
    
};

export { sendHistory };
