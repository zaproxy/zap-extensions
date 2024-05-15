
import './App.css';
import React, { useState } from 'react';
import axios from 'axios';

const App = () => {
    const [childNode,SetChildNode] = useState(null);
    const WebClickZAP = async () => {

        try {
            if (process.env.NODE_ENV === "development") {
             axios.defaults.baseURL = "http://localhost:1337"; //Specify ZAP API URL here in development environment
            } else {
                axios.defaults.baseURL = ""
            }

            const response = await axios.get('/JSON/core/view/childNodes/');
            SetChildNode(response.data.childNodes);
        } catch (error) {
            console.error('Error fetching data:', error);
        }
    };
 return (
        <div className="ZAP-1">
            <div className="w-full">
                <div className="flex flex-row justify-between text-center">
                   <div className=" w-1/3 p-4 font-serif text-center ">Website</div>
                </div>            
                <div className="flex flex-row justify-between text-center">
                    <div className="w-1/3 p-4" onClick={WebClickZAP}>
                      <p className='font-mono'>Click to fetch</p>
                      {childNode && childNode.map((node) => (
                     <p className=''>{node.name}</p>
                      ))}
                    </div>
                </div>
            </div>
        </div>
    );
}

export default App; 
