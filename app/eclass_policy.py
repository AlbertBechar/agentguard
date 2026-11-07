
# Εργαλεία που επιστρέφουν περιεχόμενο από άλλους (πιθανό source για Indirect Prompt Injection) -> Μαρκάρουν taint = True.
UNTRUSTED_TOOLS = {
    "read_forum", "get_course", "get_submissions", "read_messages",
    "get_exercise_attempts", "list_assignments", "get_exercise", "fetch_url"
}

# Κρίσιμα εργαλεία τροποποίησης κατάστασης/δεδομένων -> Απαιτούν ανθρώπινη έγκριση αν η συνομιλία είναι tainted.
HIGH_RISK_TOOLS = {
    "update_user", "reset_password", "create_user", "delete_user", "enroll_user",
    "grade_submission", "set_final_grade", "set_component_grade", "publish_grades",
    "send_message", "add_material", "post_announcement"
}