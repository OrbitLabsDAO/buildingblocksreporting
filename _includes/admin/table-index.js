/*
todo 


*/
//add a ready function
let whenDocumentReady = (f) => {
    /in/.test(document.readyState) ? setTimeout('whenDocumentReady(' + f + ')', 9) : f()
}

/*
This function handles the property select
*/
let propertySelectChange = (id, theElement) => {
    //clear the current element
    window.localStorage.currentDataItem = "";
    //store the ID
    window.localStorage.currentDataItemId = id;
    //store the table
    window.localStorage.mainTable = theTable;
    //load the URL
    if (theElement.value != 0)
        window.location.href = theElement.value;
}


whenDocumentReady(isReady = () => {

    let getTableDone = (res) => {

        if (typeof customButton === 'undefined') {
            customButton = "";
        }
        if (typeof customSelect === 'undefined') {
            customSelect = "";
        }
        
        // customButton = "";
        //parse json
        res = JSON.parse(res)
        if (allowOnlyOne == 1) {
            if (res.data.length == 0)
                document.getElementById('btn-create-cy').classList.remove('d-none');
        } else {
            document.getElementById('btn-create-cy').classList.remove('d-none');
        }
        //get the datatable
        table = $('#dataTable').DataTable();
        //process the results
        for (var i = 0; i < res.data.length; ++i) {
            //set the data 
            let theData = res.data[i];
            //build the buttons
            let deleteButton = "";
            let editButton = "";
            //parse the custom button
            customButton = customButton.replaceAll("[id]",theData.id);
            customButton = customButton.replaceAll("[name]",theData.name);
            customButton = customButton.replaceAll("[counter]",i);
            //parse the custom select
            customSelect = customSelect.replaceAll("[id]",theData.id);
            customSelect = customSelect.replaceAll("[name]",theData.name);
            customSelect = customSelect.replaceAll("[counter]",i);
  

            //check if its an admin
            if (user.isAdmin == 1) {
                editButton = `<a href="${theCrumb}edit?id=${theData.id}" class="d-sm-inline-block btn btn-sm btn-primary shadow-sm"><i class="fas fa-edit fa-sm text-white-50"></i> Edit</a>`
                deleteButton = `<a href="javascript:deleteTableItem(${theData.id},'api/database/table/','${theTable}')" class="d-sm-inline-block btn btn-sm btn-primary shadow-sm"><i class="fas fa-trash fa-sm text-white-50"></i> Delete</a>`
            }

            //set a table row array
            let tableRow = [];
            //set the amount
            let famount = 0;
            //loop through the keys
            for (const key in theData) {
                //set the data
                let tData = theData;
                //set the value
                let tmpValue = tData[key];
                //check if we have to format it
                //note this is checking the field name we could use the scheam and check if it is real 
                if (key == "amount")
                    tmpValue = formatCurencyBaht(tmpValue);
                //add the row

                //check if its a hyperlink 
                let res = isValidHttpUrl(tmpValue);
                if (res == true) {
                    tmpValue = `<a href="${tmpValue}" target="_blank">${tmpValue}</a>`
                }
                tableRow.push(tmpValue);
            }
            buildColumn = 1;
            tableRow.push(`${editButton} ${deleteButton} ${customButton} ${customSelect} `);
            //add the table rows
            var rowNode = table
                .row.add(tableRow)
                .draw()
                .node().id = theData.id;

        }
        table.columns.adjust();
    }

    //get the table results for this level.
    let getTableData = () => {
        if (typeof lookUps === 'undefined') {
            lookUps = "";
        }
        else
        {
            lookUps = JSON.stringify(lookUps);
        }

        if (foreignKeys == "")
            url = adminUrl + `database/table?checkAdmin=${checkAdmin}&tablename=${theTable}&fields=${theFields}&getOnlyTableSchema=${getOnlyTableSchema}&theData=${lookUps}`
        else
            url = adminUrl + `database/table?checkAdmin=${checkAdmin}&tablename=${theTable}&fields=${theFields}&getOnlyTableSchema=${getOnlyTableSchema}&id=${window.localStorage.currentDataItemId}&foreignId=${foreignKeys.id}&lookUps=${lookUps}`;
        xhrcall(1, url, "", "json", "", getTableDone, token);
    }

    //process the data item.
    let getMainTableDone = (res) => {
        //store it
        res = JSON.parse(res);
        //console.log(res.data)
        window.localStorage.currentDataItem = JSON.stringify(res.data[0]);
        getTableData();
    }

    //check if we have a current data item 
    if (window.localStorage.currentDataItem == "") {
        //build the json to get the main record from the main table so we can get the foreign ids.
        url = adminUrl + `database/table?tablename=${window.localStorage.mainTable}&fields=&getOnlyTableSchema=${getOnlyTableSchema}&id=${window.localStorage.currentDataItemId}&foreignId=`
        xhrcall(1, url, "", "json", "", getMainTableDone, token)
    } else {
        //build the json
        getTableData();
    }

    //show the body
    document.getElementById('showBody').classList.remove('d-none');
    if (window.localStorage.currentDataItem != "") {
        if (window.location.pathname != `/${level1name}/`) {
            let tmpJson = JSON.parse(window.localStorage.currentDataItem);
            //console.log(tmpJson.name)
            document.getElementById('recordTitle').innerHTML = tmpJson.name;
        }
    }

})