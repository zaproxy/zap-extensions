
import React, { useState, useEffect } from 'react';
import { sendChildNode } from '../../Utilities/requests'

const Accordion = () => {
    const [isAccordionOpen, setAccordionOpen] = useState(false);
    const [childNode, setChildNode] = useState(null);

    useEffect(() => {
        const fetchData = async () => {
            try {
                const childNodes = await sendChildNode('');
                setChildNode(childNodes);
            } catch (error) {
                console.error('Error fetching data:', error);
            }
        };

        fetchData();
    }, []);

    return (
        <div className="py-2">
            <button 
                onClick={() => setAccordionOpen(!isAccordionOpen)}
                className="flex justify-between w-full"
            >
                
                {isAccordionOpen ? <span className="pl-2">▼</span> : <span className="pl-2">▶</span>}
                <span class='ml-2'></span>
            </button> 
            <div 
                className={`
                    grid overflow-hidden transition-all duration-300 ease-in-out text-slate-400
                    ${isAccordionOpen ? "grid-rows-[1fr] opacity-300" : "grid-rows-[0fr] opacity-0"}
                `}>
            
                <div className="overflow-hidden">
                {childNode && childNode.map((node) => (
                     <p className='' key={node}>{node.name}</p>
                    ))}
                </div>
            </div>
        </div>
    );
}

export default Accordion;
