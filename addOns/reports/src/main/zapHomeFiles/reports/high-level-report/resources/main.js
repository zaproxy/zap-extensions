function showHide(id) {
    showHideElement(id + "reqh");
    showHideElement(id + "reqb");
    showHideElement(id + "resph");
    showHideElement(id + "respb");
}
function showHideElement(id) {
    var x = document.getElementById(id);
    if (x.style.display === "none") {
        x.style.display = "block";
    } else {
        x.style.display = "none";
    }
}

function renderSummaryChart(title, labels,data){
            
    let options = {
        responsive : true,
        title:{
            display: true,
            position: "top",
            text: title,

        },
        legend: {
            position: 'right',
            labels: {
                padding: 10
            }
        }
    }
    
    new Chart(document.getElementById("summaryChart"),
    {
        type : "pie",
        data : {
            labels : labels,
            datasets : [{
                label : title,
                data : data,
                fill : false,
                backgroundColor : [ "red", "orange", "yellow", "blue" ],
                borderWidth : 0
            }]
        },
        options : options
    });	
}					
						
function initializeSummaryBugsChartRender(){
    all_bugs_count = []
    all_labels = []
    all_colors = []						
    highest_count = 0;
    most_common_bug = "";
    most_common_bug_color = '';
}

function renderSummaryBugsChart(title, all_labels, all_bugs_count, all_colors){

    let options = {
        responsive : true,
        title:{
            display: true,
            position: "top",
            text: title,
        },
        legend: {
            position: 'right',
            labels: {
                padding: 10
            }
        }
    };

    new Chart(document.getElementById("summaryChartBugs"),
        {
            "type" : "horizontalBar",
            "data" : {
                "labels" : all_labels,
                "datasets" : [{
                    "axis": 'y',
                    "label": "number_of_occurences",
                    "fill": false,
                    "data": all_bugs_count,
                    "backgroundColor": all_colors
                }],
            },
        
            "options": options
        });
}
