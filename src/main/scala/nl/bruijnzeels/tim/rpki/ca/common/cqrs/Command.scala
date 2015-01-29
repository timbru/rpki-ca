package nl.bruijnzeels.tim.rpki.ca.common.cqrs

trait Command {
  def versionedId: VersionedId
}
