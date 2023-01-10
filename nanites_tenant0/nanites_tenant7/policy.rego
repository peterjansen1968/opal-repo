package nanites_tenant7
import future.keywords.in
default allow = false
allow {
    print(sprintf("input.request.scheme: %v", [input.request.scheme]))
    print(sprintf("input.request.method: %v", [input.request.method]))
    print(sprintf("input.request.path: %v", [input.request.path]))
    print(sprintf("input.principal: %v", [input.principal]))
	
    anyMatching
}
anyMatching {
    some i
	matches(data.nanites_tenant7.policies[i])
}
matches(policy) {
    print("matches")
    matchesAction(policy.actions[i])
    matchesPrincipal(policy.subject)
}
matchesAction(action) {
	input.request.scheme == action.request.scheme
	input.request.method == action.request.method
	input.request.path == action.request.path
}
matchesPrincipal(subject) {
    "allusers" in subject.members
}
matchesPrincipal(subject) {
    principalExists(input.principal)
    "allauthenticated" in subject.members
}
matchesPrincipal(subject) {
    input.principal in subject.members
}
principalExists(principal) {
    "" != principal
}
