from dataclasses import dataclass, field


@dataclass
class Decision:
    action: str          # "allow" | "deny" | "approve"  (η policy επιστρέφει μόνο allow/deny· το "approve" το βάζει ο Guard)
    reason: str = ""     # σύντομη εξήγηση για άνθρωπο, π.χ. "student cannot change grades"
    rule: str = ""       # σύντομο όνομα κανόνα, π.χ. "grades.write.teacher_only"


@dataclass
class TurnContext:
    user: dict                                   # η γραμμή του χρήστη από τη βάση (dict με id, username, role, ...)
    user_message: str
    tainted: bool = False                        # True αν στη συνομιλία διαβάστηκε μη-έμπιστο περιεχόμενο
    events: list = field(default_factory=list)   # λίστα από dicts, για debugging

"""
Η Decision είναι η απάντηση της policy: action (τι να γίνει), reason (γιατί, για άνθρωπο), rule (ποιος κανόνας το αποφάσισε). Τα reason και rule είναι προαιρετικά, με κενό κείμενο αν δεν τα δώσεις.
Το TurnContext κρατάει ποιος μιλάει (user), τι έγραψε (user_message) και αν η συνομιλία είναι «μολυσμένη» (tainted), δηλαδή αν διαβάστηκε περιεχόμενο που μπορεί να έχει κρυφές οδηγίες. Το events είναι μια λίστα για debugging.
Το field(default_factory=list) σημαίνει «φτιάξε καινούργια κενή λίστα για κάθε αντικείμενο». Με = [] όλα τα αντικείμενα θα μοιράζονταν την ίδια λίστα (κλασική παγίδα της Python), γι' αυτό η Python δεν το επιτρέπει στα dataclasses.
"""