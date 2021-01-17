//
//  File.swift
//  
//
//  Created by Manel Montilla on 16/1/21.
//

import Foundation

struct Node {
    var name: String
    var children: [Node] = []
    
    mutating func addNode(_ path:[String], _ node: Node) throws {
        // path =                    "a,b,c"
        // find for this child        ^
        if path.count == 0 || path[0] == "" {
            self.children.append(node)
            print("child name after adding: \(self.children[0].name)")
            return
        }
        var names = path
        let nodeName = path[0]
        for i in 0..<self.children.count {
            if self.children[i].name == nodeName {
                names.remove(at: 0)
                try self.children[i].addNode(names, node)
                return
            }
        }
        throw NSError(domain: "no dir found", code: 0)
    }
}

struct Tree {
    var root: Node
    
    mutating func addNode(_ path:URL, _ node:Node) throws {
        var components = path.pathComponents
        if components[0] == "/" {
            components.remove(at: 0)
        }
        try root.addNode(components,node)
        print("child name after returning: \(root.children[0].name)")
    }
}

