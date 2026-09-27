// Synthetic Spring + JPA sources used only as scanner input.

package fixtures;

import javax.persistence.Column;
import javax.persistence.Convert;
import javax.persistence.Entity;
import javax.persistence.Table;

@Entity
@Table(name = "citizens")
public class Citizen {

    @Column(name = "email_address")
    private String emailAddress;

    @Column(name = "aadhaar_number")
    private String aadhaarNumber;

    @Convert(converter = AttributeEncryptor.class)
    @Column(name = "pan_number")
    private String panNumber;

    @Column(name = "retention_expires_at")
    private java.time.Instant retentionExpiresAt;
}

@RestController
@RequestMapping("/api")
class CitizenController {

    @PostMapping("/citizens")
    public String create(Citizen citizen) {
        logger.info("created {}", citizen.getEmailAddress());
        return "ok";
    }

    @GetMapping("/citizens/{citizenId}")
    @PreAuthorize("hasRole('ADMIN')")
    public Citizen read(Long citizenId) {
        return repository.findOne(citizenId);
    }
}
