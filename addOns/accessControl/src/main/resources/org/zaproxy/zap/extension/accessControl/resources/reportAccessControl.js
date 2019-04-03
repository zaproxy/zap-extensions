/******************************************************************************
 *
 * Source file for the JavaScript included in the ZAP Access Control Report xsl template.
 *
 * The following JavaScript is included in every generated report and handles filtering
 * and sorting functionality.
 *
 * Before being added to the xsl file, the source needs to:
 * - be minified using any tool (e.g. http://jscompress.com/)
 * - be html encoded, for being properly added in the XSL (e.g.
 *
 ******************************************************************************/

/**
 * Click handler used for showing all the data rows.
 */
function showAll() {
	var table = document.getElementById("table");
	for (var r = 2; r < table.rows.length; r++) {
		table.rows[r].style.display = ""
	}
}
/**
 * Click handler used for showing only data rows that contain illegal accesses.
 */
function showIllegal() {
	var table = document.getElementById("table");
	for (var i = 2; i < table.rows.length; i++) {
		var row = table.rows[i];
		table.rows[i].style.display = "none";
		for (var j = 3; j < row.cells.length; j += 2) {
			if (row.cells[j].className === "ILLEGAL")
				table.rows[i].style.display = ""
		}
	}
}
/**
 * Click handler used for showing only data rows that contain only valid accesses.
 */
function showLegal() {
	var table = document.getElementById("table");
	for (var i = 2; i < table.rows.length; i++) {
		var row = table.rows[i];
		table.rows[i].style.display = "";
		for (var j = 3; j < row.cells.length; j += 2) {
			if (row.cells[j].className === "ILLEGAL")
				table.rows[i].style.display = "none"
		}
	}
}

/**
 * JavaScript Table Sorting script by tristen (https://github.com/tristen/tablesort)
 **/
(function () {
	function Tablesort(el, options) {
		if (el.tagName !== 'TABLE') {
			throw new Error('Element must be a table');
		}

		this.init(el, options || {});
	}

	Tablesort.prototype = {

		init: function (el, options) {
			var that = this,
				firstRow;
			this.thead = false;
			this.options = options;
			this.options.d = options.descending || false;

			if (el.rows && el.rows.length > 0) {
				if (el.tHead && el.tHead.rows.length > 0) {
					firstRow = el.tHead.rows[el.tHead.rows.length - 1];
					that.thead = true;
				} else {
					firstRow = el.rows[0];
				}
			}

			if (!firstRow) {
				return;
			}

			var onClick = function (e) {
				// Delete sort classes on headers that are not the current one.
				var siblings = getParent(cell, 'tr').getElementsByTagName('th');
				for (var i = 0; i < siblings.length; i++) {
					if (hasClass(siblings[i], 'sort-up') || hasClass(siblings[i], 'sort-down')) {
						if (siblings[i] !== this) {
							siblings[i].className = siblings[i].className.replace(' sort-down', '')
								.replace(' sort-up', '');
						}
					}
				}
				that.current = this;
				that.sortTable(this);
			};

			// Assume first row is the header and attach a click handler to each.
			for (var i = 0; i < firstRow.cells.length; i++) {
				var cell = firstRow.cells[i];
				if (!hasClass(cell, 'no-sort')) {
					cell.className += ' sort-header';
					addEvent(cell, 'click', onClick);
				}
			}
		},

		getFirstDataRowIndex: function () {
			// If table does not have a <thead>, assume that first row is
			// a header and skip it.
			if (!this.thead) {
				return 1;
			} else {
				return 0;
			}
		},

		sortTable: function (header, update) {
			var that = this,
				column = header.cellIndex,
				sortFunction,
				t = getParent(header, 'table'),
				item = '',
				i = that.getFirstDataRowIndex();

			if (t.rows.length <= 1) return;

			while (item === '' && i < t.tBodies[0].rows.length) {
				item = getInnerText(t.tBodies[0].rows[i].cells[column]);
				item = trim(item);
				// Exclude cell values where commented out HTML exists
				if (item.substr(0, 4) === '<!--' || item.length === 0) {
					item = '';
				}
				i++;
			}

			if (item === '') return;

			// Possible sortFunction scenarios
			var sortCaseInsensitive = function (a, b) {
				var aa = getInnerText(a.cells[that.col]).toLowerCase(),
					bb = getInnerText(b.cells[that.col]).toLowerCase();

				if (aa === bb) return 0;
				if (aa < bb) return 1;

				return -1;
			};

			var sortNumber = function (a, b) {
				var aa = getInnerText(a.cells[that.col]),
					bb = getInnerText(b.cells[that.col]);

				aa = cleanNumber(aa);
				bb = cleanNumber(bb);
				return compareNumber(bb, aa);
			};

			var sortDate = function (a, b) {
				var aa = getInnerText(a.cells[that.col]).toLowerCase(),
					bb = getInnerText(b.cells[that.col]).toLowerCase();
				return parseDate(bb) - parseDate(aa);
			};

			// Sort as number if a currency key exists or number
			if (item.match(/^-?[£\x24Û¢´€] ?\d/) || // prefixed currency
			    item.match(/^-?\d+\s*[€]/) || // suffixed currencty
			    item.match(/^-?(\d+[,\.]?)+(E[\-+][\d]+)?%?$/) // number
				) {
				sortFunction = sortNumber;
			} else if (testDate(item)) {
				sortFunction = sortDate;
			} else {
				sortFunction = sortCaseInsensitive;
			}

			this.col = column;
			var newRows = [],
				noSorts = {},
				j,
				totalRows = 0;

			for (i = 0; i < t.tBodies.length; i++) {
				for (j = 0; j < t.tBodies[i].rows.length; j++) {
					var tr = t.tBodies[i].rows[j];
					if (hasClass(tr, 'no-sort')) {
						// keep no-sorts in separate list to be able to insert
						// them back at their original position later
						noSorts[totalRows] = tr;
					} else {
						// Save the index for stable sorting
						newRows.push({
							tr: tr,
							index: totalRows
						});
					}
					totalRows++;
				}
			}

			if (!update) {
				if (that.options.d) {
					if (hasClass(header, 'sort-up')) {
						header.className = header.className.replace(/ sort-up/, '');
						header.className += ' sort-down';
					} else {
						header.className = header.className.replace(/ sort-down/, '');
						header.className += ' sort-up';
					}
				} else {
					if (hasClass(header, 'sort-down')) {
						header.className = header.className.replace(/ sort-down/, '');
						header.className += ' sort-up';
					} else {
						header.className = header.className.replace(/ sort-up/, '');
						header.className += ' sort-down';
					}
				}
			}

			// Make a stable sort function
			var stabilize = function (sort) {
				return function (a, b) {
					var unstableResult = sort(a.tr, b.tr);
					if (unstableResult === 0) {
						return a.index - b.index;
					}
					return unstableResult;
				};
			};

			// Make an `anti-stable` sort function. If two elements are equal
			// under the original sort function, then there relative order is
			// reversed.
			var antiStabilize = function (sort) {
				return function (a, b) {
					var unstableResult = sort(a.tr, b.tr);
					if (unstableResult === 0) {
						return b.index - a.index;
					}
					return unstableResult;
				};
			};

			// Before we append should we reverse the new array or not?
			// If we reverse, the sort needs to be `anti-stable` so that
			// the double negatives cancel out
			if (hasClass(header, 'sort-down')) {
				newRows.sort(antiStabilize(sortFunction));
				newRows.reverse();
			} else {
				newRows.sort(stabilize(sortFunction));
			}

			// append rows that already exist rather than creating new ones
			var noSortsSoFar = 0;
			for (i = 0; i < totalRows; i++) {
				var whatToInsert;
				if (noSorts[i]) {
					// We have a no-sort row for this position, insert it here.
					whatToInsert = noSorts[i];
					noSortsSoFar++;
				} else {
					whatToInsert = newRows[i - noSortsSoFar].tr;
				}
				// appendChild(x) moves x if already present somewhere else in the DOM
				t.tBodies[0].appendChild(whatToInsert);
			}
		},

		refresh: function () {
			if (this.current !== undefined) {
				this.sortTable(this.current, true);
			}
		}
	};

	var week = /(Mon|Tue|Wed|Thu|Fri|Sat|Sun)\.?\,?\s*/i,
		commonDate = /\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}/,
		month = /(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/i;

	var testDate = function (date) {
			return (
				       date.search(week) !== -1 ||
				       date.search(commonDate) !== -1 ||
				       date.search(month !== -1)
				       ) !== -1 && !isNaN(parseDate(date));
		},

		parseDate = function (date) {
			date = date.replace(/\-/g, '/');
			date = date.replace(/(\d{1,2})[\/\-](\d{1,2})[\/\-](\d{2})/, '$1/$2/$3'); // format before getTime
			return new Date(date).getTime();
		},

		getParent = function (el, pTagName) {
			if (el === null) {
				return null;
			} else if (el.nodeType === 1 && el.tagName.toLowerCase() === pTagName.toLowerCase()) {
				return el;
			} else {
				return getParent(el.parentNode, pTagName);
			}
		},

		getInnerText = function (el) {
			var that = this;

			if (typeof el === 'string' || typeof el === 'undefined') {
				return el;
			}

			var str = el.getAttribute('data-sort') || '';

			if (str) {
				return str;
			}
			else if (el.textContent) {
				return el.textContent;
			}
			else if (el.innerText) {
				return el.innerText;
			}

			var cs = el.childNodes,
				l = cs.length;

			for (var i = 0; i < l; i++) {
				switch (cs[i].nodeType) {
					case 1:
						// ELEMENT_NODE
						str += that.getInnerText(cs[i]);
						break;
					case 3:
						// TEXT_NODE
						str += cs[i].nodeValue;
						break;
				}
			}

			return str;
		},

		compareNumber = function (a, b) {
			var aa = parseFloat(a),
				bb = parseFloat(b);

			a = isNaN(aa) ? 0 : aa;
			b = isNaN(bb) ? 0 : bb;
			return a - b;
		},

		trim = function (s) {
			return s.replace(/^\s+|\s+$/g, '');
		},

		cleanNumber = function (i) {
			return i.replace(/[^\-?0-9.]/g, '');
		},

		hasClass = function (el, c) {
			return (' ' + el.className + ' ').indexOf(' ' + c + ' ') > -1;
		},

	// http://ejohn.org/apps/jselect/event.html
		addEvent = function (object, event, method) {
			if (object.attachEvent) {
				object['e' + event + method] = method;
				object[event + method] = function () {
					object['e' + event + method](window.event);
				};
				object.attachEvent('on' + event, object[event + method]);
			} else {
				object.addEventListener(event, method, false);
			}
		};

	if (typeof module !== 'undefined' && module.exports) {
		module.exports = Tablesort;
	} else {
		window.Tablesort = Tablesort;
	}
})();
new Tablesort(document.getElementById("table"));

/**
 * JavaScript Table Filtering script by Chris Coyier (http://codepen.io/chriscoyier/pen/tIuBL)
 **/
(function (document) {
	'use strict';

	var LightTableFilter = (function (Arr) {

		var _input;

		function _onInputEvent(e) {
			_input = e.target;
			var tables = document.getElementsByClassName(_input.getAttribute('data-table'));
			Arr.forEach.call(tables, function (table) {
				Arr.forEach.call(table.tBodies, function (tbody) {
					Arr.forEach.call(tbody.rows, _filter);
				});
			});
		}

		function _filter(row) {
			var text = row.textContent.toLowerCase(), val = _input.value.toLowerCase();
			row.style.display = text.indexOf(val) === -1 ? 'none' : 'table-row';
		}

		return {
			init: function () {
				var inputs = document.getElementsByClassName('light-table-filter');
				Arr.forEach.call(inputs, function (input) {
					input.oninput = _onInputEvent;
				});
			}
		};
	})(Array.prototype);

	document.addEventListener('readystatechange', function () {
		if (document.readyState === 'complete') {
			LightTableFilter.init();
		}
	});
})(document);