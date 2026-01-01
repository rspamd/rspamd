# Rspamd WebUI Architecture

## Overview

The Rspamd WebUI is a single-page application (SPA) providing a web interface for monitoring and managing Rspamd. It communicates with Rspamd's Controller API and supports multiple server instances.

**Main capabilities:**
- Real-time statistics and throughput monitoring
- Message processing history inspection
- Message scanning and analysis
- Bayes classifier and Fuzzy storage training
- Symbol and action configuration
- Map editing
- Selector testing
- Multi-server management

## Technology Stack

### Module System
- **RequireJS** - AMD (Asynchronous Module Definition) pattern for modular code organization

### Core Libraries
- **jQuery** - DOM manipulation, event handling, AJAX
- **Bootstrap** - UI framework for responsive layout and components

### Visualization & Data Display
- **D3.js** - Base visualization library
- **D3Evolution** - Time-series line charts (throughput graphs)
- **D3Pie** - Pie charts (action distribution)
- **FooTable** - Responsive data tables with sorting, filtering, and pagination

### Code Editing
- **CodeJar** - Lightweight code editor
- **CodeJar Line Numbers** - Line numbering extension for CodeJar
- **Prism.js** - Syntax highlighting

### Utilities
- **NProgress** - Progress bars for async operations
- **Visibility.js** - Page Visibility API wrapper for timer management
- **Font Awesome** - Icon library
- **jQuery Sticky Tabs** - Persistent tab state via URL hash

### Theme System
Custom implementation supporting light/dark/auto modes with system preference detection.

## Project Structure

```
interface/
├── index.html              # Main HTML file with tab structure
├── css/                    # Stylesheets
│   ├── bootstrap.min.css
│   ├── rspamd.css         # Custom styles
│   └── ...                # Third-party CSS
├── js/
│   ├── main.js            # Entry point & RequireJS configuration
│   ├── app/               # Application modules
│   │   ├── common.js      # Shared utilities and API client
│   │   ├── rspamd.js      # Main application logic, auth, tab management
│   │   ├── stats.js       # Statistics tab (status widgets)
│   │   ├── history.js     # History tab (message log, errors)
│   │   ├── graph.js       # Throughput tab (time-series graphs)
│   │   ├── symbols.js     # Symbols tab (symbol scores editing)
│   │   ├── config.js      # Configuration tab (actions, maps)
│   │   ├── upload.js      # Scan tab (message upload/scanning)
│   │   ├── selectors.js   # Selectors tab (testing selectors)
│   │   ├── libft.js       # FooTable utilities (history table rendering)
│   │   └── footable-fontawesome.js  # FooTable Font Awesome integration
│   └── lib/               # Third-party libraries (minified)
├── img/                   # Images and logos
└── README.md              # Setup instructions
```

## Module System

The WebUI uses **RequireJS** (AMD pattern) for modular code organization.

**Module definition pattern:**
```javascript
define(["dependency1", "dependency2"], (dep1, dep2) => {
    const ui = {};
    ui.publicMethod = function() { /* ... */ };
    return ui;
});
```

**Entry point:** `js/main.js` - configures RequireJS, initializes theme, loads main app module

**Module loading:**
- Main app module (`app/rspamd`) loads on page load
- Tab-specific modules lazy-load when tabs are activated

## Key Components

### Authentication & Connection
`js/app/rspamd.js` - `ui.connect()`

Handles password authentication, stores credentials in `sessionStorage`, detects read-only mode

### Tab Management & Navigation
`js/app/rspamd.js` - `tabClick()`

Manages tab switching, lazy-loads tab-specific modules, handles auto-refresh

### Auto-Refresh System
`js/app/rspamd.js` - `setAutoRefresh()`

Periodically refreshes tab data, pauses when page hidden (via Visibility.js), shows countdown timer

### API Communication
`js/app/common.js` - `ui.query(url, options)`

Sends HTTP requests to Controller API, supports multi-server queries, handles authentication and errors

### Theme System
`js/main.js` - Theme initialization and `window.rspamd.theme` API

Manages light/dark/auto theme switching, persists preferences, responds to system theme changes

### Statistics Display
`js/app/stats.js`

Fetches and displays server statistics (Status tab): version, uptime, message counts, action distribution

### Throughput Graphs
`js/app/graph.js`

Renders time-series graphs and pie charts (Throughput tab) using D3Evolution and D3Pie

### Message History
`js/app/history.js` (data fetching), `js/app/libft.js` (table rendering)

Displays processed message history (History tab), handles FooTable initialization, row expansion, symbol details

### Configuration Management
`js/app/config.js`

Manages actions and maps (Configuration tab): load, edit, save settings

### Symbol Management
`js/app/symbols.js`

Displays and edits symbol scores (Symbols tab)

### Message Scanning & Learning
`js/app/upload.js`

Handles message upload, scanning, Bayes classifier training, fuzzy hash management (Scan tab)

### Selector Testing
`js/app/selectors.js`

Tests Rspamd selectors against messages (Selectors tab)

### Table Utilities
`js/app/libft.js`

Shared utilities for FooTable: data preprocessing, table initialization, pagination, sorting

### FooTable Icons
`js/app/footable-fontawesome.js`

Integrates Font Awesome icons with FooTable

## Data Flow

**Typical interaction pattern:**
1. User action (click, input) → Event handler
2. Data preparation
3. `common.query()` → API request(s) to server(s)
4. Response processing
5. UI update (DOM, tables, charts)

## Common Patterns

### Event Handlers
Use function expressions `function() {}` when you need `this` context (event target element), otherwise use arrow functions `() => {}`.

### API Calls
Most API communication goes through `common.query(endpoint, options)` which handles multi-server requests, authentication, progress tracking, and error handling.

### Table Management
Tables use FooTable library. Two main patterns:
- **Initial load**: destroy old table → process data → initialize FooTable → bind event handlers
- **Update data**: use FooTable API to update existing table without re-initialization

### Module Structure
Each tab module returns a `ui` object with public methods (e.g., `ui.getSymbols()`, `ui.draw()`). These methods are called when tabs are activated.

## State Management

**Persistent storage (localStorage):**
- Theme preference
- Locale settings
- AJAX timeout
- Page size preferences

**Session storage (sessionStorage):**
- Authentication password
- Server credentials and capabilities
- Error suppression flags

**Global state:**
- `common.neighbours[]` - Configured servers
- `common.tables{}` - FooTable instances
- `timer_id[]` - Active refresh timers
- `checked_server` - Currently selected server

## Technical Requirements

**Browser capabilities needed:**
- Modern JavaScript (ES6+: arrow functions, const/let, template literals)
- Page Visibility API
- CSS Custom Properties

**Network:**
- Browser must have network access to all configured controllers
- WebUI makes API requests from the browser to each controller independently (the controller serving the WebUI does not act as an intermediary)
