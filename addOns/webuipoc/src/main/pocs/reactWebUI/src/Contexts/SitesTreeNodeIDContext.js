import React, { useState, createContext } from 'react';


export const nodeIDContext = createContext();

export const NodeIDProvider = ({ children }) => {
const [nodeID, setNodeID] = useState(0);
  return (
    <nodeIDContext.Provider value={{ nodeID, setNodeID }}>
      {children}
    </nodeIDContext.Provider>
  );
};
 