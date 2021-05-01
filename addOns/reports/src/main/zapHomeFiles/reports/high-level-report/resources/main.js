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
            
    var options = {
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


function initializeAssetsChartRender(){
    assets = [];
    bug_counts = [];
    highest_bugs_count = 0;
    highest_ranked_bug = "";
}								

function generate_random_bug_counts(min, max) { 
        return Math.floor(Math.random() * (max - min) + min);
    };
						
function renderAssetsChart(title, assets, bug_counts, asset_with_most_bugs, asset_with_most_bugs_unprocessed){
    try{
        crafted_asset_link_element = document.createElement('a');
        crafted_asset_link_element_text = document.createTextNode(asset_with_most_bugs);
        crafted_asset_link_element.appendChild(crafted_asset_link_element_text);
        crafted_asset_link_element.title = asset_with_most_bugs;
        crafted_asset_link_element.href = asset_with_most_bugs_unprocessed;
        document.getElementById('asset_bugs_count').appendChild(crafted_asset_link_element) ;
    }
    catch(e){
        console.log(e)
    }

    chart_type = "bar";
    if(assets.length > 5) chart_type = "polarArea";

    var options = {
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

    new Chart(document.getElementById("assetsChart"),
            {
                type : chart_type,
                data : {
                    labels : assets,
                    datasets : [ {
                        label : title,
                        data : bug_counts,
                    } ]
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

function renderSummaryBugsChart(){

    var options = {
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