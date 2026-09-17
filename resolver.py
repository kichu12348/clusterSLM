from graph import get_module_name

def build_symbol_index(files, repo_path):
    """
    Creates a dictionary mapping short symbol names to their Fully Qualified Names (FQN).
    """
    index = {}
    
    for file in files:
        mod_name = get_module_name(file.path, repo_path.parent)
        
        # Index classes
        for cls in file.classes:
            index.setdefault(cls, []).append(f"{mod_name}.{cls}")
            
        # Index functions/methods
        for caller in file.call_map.keys():
            if caller != "<module>":
                fqn = f"{mod_name}.{caller}"
                
                # Index by the full Class.Method (e.g., AdminService.run_network_diagnostic)
                index.setdefault(caller, []).append(fqn)
                
                # Index by just the method name (e.g., run_network_diagnostic)
                short_name = caller.split('.')[-1]
                index.setdefault(short_name, []).append(fqn)
                
    return index

def resolve_call_graph(files, repo_path, index):
    """
    Matches raw AST calls to their FQNs using the symbol index.
    """
    edges = set() # Using a set to prevent duplicate edges
    
    for file in files:
        mod_name = get_module_name(file.path, repo_path.parent)
        
        for caller, calls in file.call_map.items():
            caller_fqn = mod_name if caller == "<module>" else f"{mod_name}.{caller}"
            
            for call in calls:
                # Strip object prefixes (e.g., self.admin_service.run_network_diagnostic -> run_network_diagnostic)
                call_base = call.split('.')[-1]
                
                # 1. Try exact match (e.g., DatabaseManager.get_instance)
                if call in index:
                    for target_fqn in index[call]:
                        edges.add((caller_fqn, target_fqn))
                        
                # 2. Try method name match (e.g., run_network_diagnostic)
                elif call_base in index:
                    for target_fqn in index[call_base]:
                        edges.add((caller_fqn, target_fqn))
                        
                # 3. External/System Call (e.g., subprocess.run)
                else:
                    edges.add((caller_fqn, call))
                    
    return edges