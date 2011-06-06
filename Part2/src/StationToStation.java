import de.tubs.cs.iti.krypto.protokoll.*;

public final class StationToStation implements Protocol {

	static private int MinPlayer = 2; // Minimal number of players
	static private int MaxPlayer = 2; // Maximal number of players
	static private String NameOfTheGame = "Station To Station";
	private Communicator Com;

	public void setCommunicator(Communicator com) {
		Com = com;
	}

	public void sendFirst()
	/**
	 * Aktionen der beginnenden Partei. Bei den 2-Parteien-Protokollen seien
	 * dies die Aktionen von Alice.
	 */
	{
		System.out.println("alice test");
	}

	public void receiveFirst()
	/**
	 * Aktionen der uebrigen Parteien. Bei den 2-Parteien-Protokollen seien dies
	 * die Aktionen von Bob.
	 */
	{
	}

	public String nameOfTheGame() {
		return NameOfTheGame;
	}

	public int minPlayer() {
		return MinPlayer;
	}

	public int maxPlayer() {
		return MaxPlayer;
	}
}
