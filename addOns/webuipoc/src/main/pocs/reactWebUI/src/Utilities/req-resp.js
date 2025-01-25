import axios from 'axios';

const sendMessage = async (id) => {
 try {
        const response = await axios.get(`/JSON/core/view/message?id=${id}`);
        return response.data.message;
       } catch (error) {
        console.error('Error fetching data:', error);
        throw error;
    }
};

export { sendMessage };
