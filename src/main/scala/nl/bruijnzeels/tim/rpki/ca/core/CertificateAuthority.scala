package nl.bruijnzeels.tim.rpki.ca.core

case class CertificateAuthority(name: String) {

}

object CertificateAuthority {
  
  def instance(created: CaCreated) = {
    CertificateAuthority(created.name)
  }
  
}
