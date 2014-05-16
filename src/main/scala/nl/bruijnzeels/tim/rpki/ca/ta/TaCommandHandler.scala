package nl.bruijnzeels.tim.rpki.ca.ta

trait TaCommandHandler[C <: TaCommand] {
  def handle(taCommand: C): List[TaEvent]
}

object CreateTaCommandHandler extends TaCommandHandler[CreateTa] {
  override def handle(command: CreateTa) = {
    TrustAnchor.create(command.name)
               .initialise(command.resources, command.taCertificateUri, command.publicationUri)
               .events
  }
}
